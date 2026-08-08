package ltechnologies.onionphone.pgpshield.data.vault

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.io.FileNotFoundException
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.LockSupport
import javax.crypto.AEADBadTagException
import javax.inject.Inject
import javax.inject.Singleton
import ltechnologies.onionphone.pgpshield.data.security.VaultAccessPolicy
import ltechnologies.onionphone.pgpshield.data.security.VaultMasterKeyFactory
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import timber.log.Timber

/**
 * Encrypted on-disk storage for armored PGP key ring blobs.
 *
 * **Generation publish (lock-free I/O):** each [write] creates a unique filename
 * `kr_<id>[_pub]_g<gen>.gpg` via [AtomicLong] so EncryptedFile AAD matches the path
 * permanently. Concurrent reads of distinct paths need no JVM lock.
 *
 * **Keyset warm:** [AtomicInteger] CAS state machine (COLD → WARMING → READY) — no
 * `synchronized`. Waiters park with exponential backoff until READY.
 *
 * **Migrate edge:** at-most-one in-place upgrade per path via ConcurrentHashMap CAS set.
 *
 * Legacy flat names (`kr_<id>.gpg`) remain readable; migrate-on-read re-encrypts in place
 * best-effort.
 */
@Singleton
class EncryptedBlobStore @Inject constructor(
    @ApplicationContext private val context: Context,
    private val vaultAccessPolicy: VaultAccessPolicy,
) : KeyBlobStore {
    private val masterKeyV2: MasterKey by lazy { VaultMasterKeyFactory.createVaultKey(context) }
    private val masterKeyLegacy: MasterKey by lazy { VaultMasterKeyFactory.createLegacyVaultKey(context) }

    /** 0=COLD, 1=WARMING, 2=READY */
    private val keysetState = AtomicInteger(KEYSET_COLD)
    private val generation = AtomicLong(System.currentTimeMillis())
    private val migratingPaths = ConcurrentHashMap.newKeySet<String>()

    private val dir: File by lazy {
        File(context.filesDir, "keyrings").also { it.mkdirs() }
    }

    /** Warm StrongBox/TEE MasterKey + isolated Tink keyset (idempotent, safe to call early). */
    fun warmKeyset() {
        ensureKeysetReady()
    }

    override fun write(keyId: Long, data: ByteArray): String = write(keyId, data, suffix = "")

    override fun writePublic(keyId: Long, data: ByteArray): String = write(keyId, data, suffix = "_pub")

    private fun write(keyId: Long, data: ByteArray, suffix: String): String {
        vaultAccessPolicy.assertSecretsAccessible()
        ensureKeysetReady()
        val path = File(dir, "kr_${keyId}${suffix}_g${generation.incrementAndGet()}.gpg")
        writeAndVerify(path, data)
        return path.absolutePath
    }

    override fun read(path: String): ByteArray {
        vaultAccessPolicy.assertSecretsAccessible()
        ensureKeysetReady()
        val file = File(path)
        recoverIncompleteIfNeeded(file)

        if (!file.isFile) {
            throw FileNotFoundException("file doesn't exist: ${file.name}")
        }

        val errors = mutableListOf<Throwable>()
        for (attempt in readAttempts()) {
            try {
                val plain = openEncrypted(file, attempt.masterKey, attempt.slot)
                    .openFileInput().use { PgpIo.readLimited(it) }
                if (attempt.slot != KeysetSlot.V2) {
                    // Best-effort in-place upgrade; next write() publishes a new generation.
                    migrateToV2InPlace(file, plain)
                }
                return plain
            } catch (e: Exception) {
                errors += e
                Timber.d(e, "vault read failed with %s", attempt.slot)
            }
        }

        tryRecoverBuggyMigrateAad(file)?.let { plain ->
            Timber.w("Recovered vault blob %s from rename/AAD mismatch", file.name)
            migrateToV2InPlace(file, plain)
            return plain
        }

        throw wrapVaultError(errors)
    }

    override fun delete(path: String) {
        val file = File(path)
        secureDelete(file)
        File(file.parentFile, file.name + SUFFIX_RAWBAK).takeIf { !file.exists() }?.let { secureDelete(it) }
        File(file.parentFile, file.name + SUFFIX_MIGRATE).delete()
        File(file.parentFile, file.name + SUFFIX_BAK).delete()
    }

    override fun ensureBlobPresent(path: String): Boolean {
        val file = File(path)
        recoverIncompleteIfNeeded(file)
        return file.isFile
    }

    /**
     * Lock-free keyset warm: exactly one thread runs Tink/prefs init; others park until READY.
     * Failed warmers restore COLD so a peer can CAS-claim the edge again.
     */
    private fun ensureKeysetReady() {
        when (keysetState.get()) {
            KEYSET_READY -> return
            KEYSET_WARMING -> {
                awaitKeysetReady()
                return
            }
        }
        if (!keysetState.compareAndSet(KEYSET_COLD, KEYSET_WARMING)) {
            awaitKeysetReady()
            return
        }
        try {
            dir.mkdirs()
            val probe = File(dir, ".keyset_warm_g0.gpg")
            try {
                openEncrypted(probe, masterKeyV2, KeysetSlot.V2).openFileOutput().use { it.write(byteArrayOf(0)) }
            } catch (e: Exception) {
                if (!isKeysetCorruption(e)) throw e
                Timber.e(e, "Warm keyset corrupted — resetting isolated v2 prefs")
                clearKeysetPrefs(KeysetSlot.V2)
                openEncrypted(probe, masterKeyV2, KeysetSlot.V2).openFileOutput().use { it.write(byteArrayOf(0)) }
            } finally {
                probe.delete()
            }
            keysetState.set(KEYSET_READY)
        } catch (e: Exception) {
            keysetState.set(KEYSET_COLD)
            throw e
        }
    }

    private fun awaitKeysetReady() {
        var backoffNs = 1_000L
        while (true) {
            when (keysetState.get()) {
                KEYSET_READY -> return
                KEYSET_COLD -> {
                    ensureKeysetReady()
                    return
                }
                else -> {
                    LockSupport.parkNanos(backoffNs)
                    backoffNs = (backoffNs shl 1).coerceAtMost(1_000_000L)
                }
            }
        }
    }

    /**
     * Atomically drops READY/WARMING → COLD. Concurrent waiters re-CAS warm on the edge.
     * Used only on rare keyset-corruption recovery paths.
     */
    private fun invalidateKeyset() {
        while (true) {
            when (val s = keysetState.get()) {
                KEYSET_COLD -> return
                else -> if (keysetState.compareAndSet(s, KEYSET_COLD)) return
            }
        }
    }

    private fun tryRecoverBuggyMigrateAad(file: File): ByteArray? {
        val parent = file.parentFile ?: return null
        val migrateName = file.name + SUFFIX_MIGRATE
        val migrateFile = File(parent, migrateName)

        fun decryptAsMigrateName(source: File): ByteArray? {
            val probe = File(parent, migrateName)
            val createdProbe = probe.absolutePath != source.absolutePath
            return try {
                if (createdProbe) {
                    if (probe.exists()) probe.delete()
                    source.copyTo(probe, overwrite = true)
                }
                for (slot in listOf(KeysetSlot.V2, KeysetSlot.V2_ON_DEFAULT)) {
                    try {
                        return openEncrypted(probe, masterKeyV2, slot)
                            .openFileInput().use { PgpIo.readLimited(it) }
                    } catch (_: Exception) {
                        // try next slot
                    }
                }
                null
            } catch (_: Exception) {
                null
            } finally {
                if (createdProbe) probe.delete()
            }
        }

        migrateFile.takeIf { it.isFile }?.let { leftover ->
            decryptAsMigrateName(leftover)?.let { return it }
        }
        return decryptAsMigrateName(file)
    }

    private fun readAttempts(): List<ReadAttempt> = listOf(
        ReadAttempt(masterKeyV2, KeysetSlot.V2),
        ReadAttempt(masterKeyV2, KeysetSlot.V2_ON_DEFAULT),
        ReadAttempt(masterKeyLegacy, KeysetSlot.LEGACY),
    )

    private fun writeAndVerify(path: File, data: ByteArray) {
        try {
            openEncrypted(path, masterKeyV2, KeysetSlot.V2).openFileOutput().use { it.write(data) }
            val roundTrip = openEncrypted(path, masterKeyV2, KeysetSlot.V2)
                .openFileInput().use { PgpIo.readLimited(it) }
            check(roundTrip.contentEquals(data)) { "Vault write verify mismatch" }
        } catch (e: Exception) {
            path.delete()
            if (!isKeysetCorruption(e)) throw e
            Timber.e(e, "Isolated vault keyset unreadable — resetting %s and retrying write", KeysetSlot.V2.prefName)
            clearKeysetPrefs(KeysetSlot.V2)
            invalidateKeyset()
            ensureKeysetReady()
            openEncrypted(path, masterKeyV2, KeysetSlot.V2).openFileOutput().use { it.write(data) }
            val roundTrip = openEncrypted(path, masterKeyV2, KeysetSlot.V2)
                .openFileInput().use { PgpIo.readLimited(it) }
            check(roundTrip.contentEquals(data)) { "Vault write verify mismatch after keyset reset" }
        }
    }

    private fun clearKeysetPrefs(slot: KeysetSlot) {
        @Suppress("ApplySharedPref")
        context.getSharedPreferences(slot.prefName, Context.MODE_PRIVATE).edit().clear().commit()
        val prefsDir = File(context.applicationInfo.dataDir, "shared_prefs")
        File(prefsDir, "${slot.prefName}.xml").delete()
        File(prefsDir, "${slot.prefName}.xml.bak").delete()
    }

    private fun isKeysetCorruption(e: Throwable): Boolean {
        var cur: Throwable? = e
        while (cur != null) {
            if (cur is AEADBadTagException) return true
            val msg = cur.message.orEmpty()
            if (msg.contains("Keyset", ignoreCase = true) ||
                msg.contains("tag mismatch", ignoreCase = true) ||
                msg.contains("MAC verification", ignoreCase = true)
            ) {
                return true
            }
            cur = cur.cause
        }
        return false
    }

    private fun migrateToV2InPlace(file: File, plain: ByteArray) {
        val key = file.absolutePath
        // Lock-free single-flight: ConcurrentHashMap.add is CAS — losers skip migrate.
        if (!migratingPaths.add(key)) return
        try {
            runCatching {
                val rawBak = File(file.parentFile, file.name + SUFFIX_RAWBAK)
                if (file.isFile) {
                    if (rawBak.exists()) secureDelete(rawBak)
                    if (!rawCopy(file, rawBak)) return@runCatching
                    secureDelete(file)
                }
                try {
                    writeAndVerify(file, plain)
                    if (rawBak.exists()) secureDelete(rawBak)
                    Timber.i("Migrated vault blob %s to isolated MasterKey v2 keyset", file.name)
                } catch (e: Exception) {
                    file.delete()
                    if (rawBak.isFile) rawCopy(rawBak, file)
                    throw e
                }
            }.onFailure { Timber.w(it, "Vault migrate deferred for %s", file.name) }
        } finally {
            migratingPaths.remove(key)
        }
    }

    private fun recoverIncompleteIfNeeded(file: File) {
        if (file.isFile) return
        val parent = file.parentFile ?: return
        val rawBak = File(parent, file.name + SUFFIX_RAWBAK)
        if (rawBak.isFile) {
            if (rawCopy(rawBak, file)) {
                Timber.w("Restored vault blob %s from crash rawbak", file.name)
                secureDelete(rawBak)
                return
            }
        }
        val legacyBak = File(parent, file.name + SUFFIX_BAK)
        if (legacyBak.isFile && legacyBak.renameTo(file)) {
            Timber.w("Restored vault blob %s from legacy migrate bak", file.name)
        } else if (legacyBak.isFile && rawCopy(legacyBak, file)) {
            Timber.w("Restored vault blob %s from legacy migrate bak (copy)", file.name)
            secureDelete(legacyBak)
        }
    }

    private fun rawCopy(from: File, to: File): Boolean {
        return try {
            if (to.exists()) to.delete()
            from.inputStream().use { input ->
                to.outputStream().use { output -> input.copyTo(output) }
            }
            to.length() == from.length()
        } catch (_: Exception) {
            false
        }
    }

    private fun secureDelete(file: File) {
        if (!file.exists()) return
        runCatching {
            val len = file.length().coerceAtMost(4096L).toInt()
            if (len > 0) {
                java.io.RandomAccessFile(file, "rw").use { raf ->
                    raf.seek(0)
                    raf.write(ByteArray(len))
                }
            }
        }
        file.delete()
    }

    private fun openEncrypted(file: File, masterKey: MasterKey, slot: KeysetSlot): EncryptedFile =
        EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        )
            .setKeysetPrefName(slot.prefName)
            .setKeysetAlias(slot.keysetAlias)
            .build()

    private fun wrapVaultError(errors: List<Throwable>): Exception {
        val primary = errors.firstOrNull() ?: IllegalStateException("Vault decrypt failed")
        val root = generateSequence(primary) { it.cause }.firstOrNull {
            it is AEADBadTagException
        } ?: primary
        val ex = IllegalStateException(
            "Vault decrypt failed (${root.javaClass.simpleName}). " +
                "Secret blob may be corrupted or encrypted with an incompatible MasterKey.",
            primary,
        )
        errors.drop(1).forEach { ex.addSuppressed(it) }
        return ex
    }

    private data class ReadAttempt(val masterKey: MasterKey, val slot: KeysetSlot)

    private enum class KeysetSlot(val prefName: String, val keysetAlias: String) {
        LEGACY(
            prefName = "__androidx_security_crypto_encrypted_file_pref__",
            keysetAlias = "__androidx_security_crypto_encrypted_file_keyset__",
        ),
        V2_ON_DEFAULT(
            prefName = "__androidx_security_crypto_encrypted_file_pref__",
            keysetAlias = "__androidx_security_crypto_encrypted_file_keyset__",
        ),
        V2(
            prefName = "__pgp_shield_encrypted_file_pref_v2__",
            keysetAlias = "__pgp_shield_encrypted_file_keyset_v2__",
        ),
    }

    companion object {
        private const val KEYSET_COLD = 0
        private const val KEYSET_WARMING = 1
        private const val KEYSET_READY = 2

        const val SUFFIX_RAWBAK = ".rawbak"
        const val SUFFIX_BAK = ".bak"
        const val SUFFIX_MIGRATE = ".migrate"
    }
}
