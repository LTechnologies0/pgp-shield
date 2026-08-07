package ltechnologies.onionphone.pgpshield.data.vault

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.io.FileNotFoundException
import javax.inject.Inject
import javax.inject.Singleton
import ltechnologies.onionphone.pgpshield.data.security.VaultAccessPolicy
import ltechnologies.onionphone.pgpshield.data.security.VaultMasterKeyFactory
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import timber.log.Timber

/**
 * Encrypted on-disk storage for armored PGP key ring blobs.
 *
 * Uses AndroidX [EncryptedFile] with AES-256-GCM and a StrongBox-preferred [MasterKey]
 * (TEE Keystore fallback). Legacy blobs encrypted with the default MasterKey alias are
 * still readable and re-written under the v2 StrongBox key on next write.
 */
@Singleton
class EncryptedBlobStore @Inject constructor(
    @ApplicationContext private val context: Context,
    private val vaultAccessPolicy: VaultAccessPolicy,
) : KeyBlobStore {
    private val masterKeyV2: MasterKey by lazy { VaultMasterKeyFactory.createVaultKey(context) }
    private val masterKeyLegacy: MasterKey by lazy { VaultMasterKeyFactory.createLegacyVaultKey(context) }

    private val dir: File by lazy {
        File(context.filesDir, "keyrings").also { it.mkdirs() }
    }

    override fun write(keyId: Long, data: ByteArray): String = write(keyId, data, suffix = "")

    override fun writePublic(keyId: Long, data: ByteArray): String = write(keyId, data, suffix = "_pub")

    private fun write(keyId: Long, data: ByteArray, suffix: String): String {
        vaultAccessPolicy.assertSecretsAccessible()
        val path = fileFor(keyId, suffix)
        if (path.exists()) {
            delete(path.absolutePath)
        }
        openEncrypted(path, masterKeyV2).openFileOutput().use { it.write(data) }
        return path.absolutePath
    }

    override fun read(path: String): ByteArray {
        vaultAccessPolicy.assertSecretsAccessible()
        val file = File(path)
        if (!file.isFile) {
            throw FileNotFoundException("file doesn't exist: ${file.name}")
        }
        return try {
            openEncrypted(file, masterKeyV2).openFileInput().use { PgpIo.readLimited(it) }
        } catch (e: Exception) {
            Timber.d(e, "v2 vault read failed — trying legacy MasterKey")
            val plain = openEncrypted(file, masterKeyLegacy).openFileInput().use { PgpIo.readLimited(it) }
            // Transparent upgrade to StrongBox-backed key on next successful read of secrets.
            runCatching {
                val tmp = File(file.parentFile, file.name + ".migrate")
                if (tmp.exists()) tmp.delete()
                openEncrypted(tmp, masterKeyV2).openFileOutput().use { it.write(plain) }
                if (!tmp.renameTo(file)) {
                    file.delete()
                    tmp.renameTo(file)
                }
                Timber.i("Migrated vault blob %s to StrongBox/TEE MasterKey v2", file.name)
            }.onFailure { Timber.w(it, "Vault migrate deferred for %s", file.name) }
            plain
        }
    }

    override fun delete(path: String) {
        val file = File(path)
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

    private fun openEncrypted(file: File, masterKey: MasterKey): EncryptedFile =
        EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build()

    private fun fileFor(keyId: Long, suffix: String = ""): File = File(dir, "kr_$keyId$suffix.gpg")
}
