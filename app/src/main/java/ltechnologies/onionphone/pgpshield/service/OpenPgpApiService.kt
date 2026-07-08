package ltechnologies.onionphone.pgpshield.service

/**
 * Bound service implementing the standard OpenPGP API (`IOpenPgpService2`).
 *
 * Provides wire-compatible encrypt/decrypt/sign/verify, key-id lookup and
 * backup operations to third-party clients over binder IPC, brokering access to
 * the app's key store and crypto engine.
 */

import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.ParcelFileDescriptor
import dagger.hilt.android.AndroidEntryPoint
import ltechnologies.onionphone.pgpshield.api.GrantApiAccessActivity
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.data.db.ApiAllowedKeyDao
import ltechnologies.onionphone.pgpshield.data.db.ApiAppDao
import ltechnologies.onionphone.pgpshield.data.db.UserIdDao
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import ltechnologies.onionphone.pgpshield.openpgp.OpenPgpConstants
import ltechnologies.onionphone.pgpshield.util.CryptoErrors
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.OpenPgpError
import timber.log.Timber

/**
 * Hilt-injected [Service] exposing the OpenPGP API v11 binder interface.
 *
 * Requests arrive on the binder thread and are dispatched onto a background
 * dispatcher for crypto work. Callers are authenticated by UID, permission is
 * gated per-package, and unknown callers receive a `USER_INTERACTION_REQUIRED`
 * result pointing at [GrantApiAccessActivity]. Passphrase buffers are wiped
 * after use.
 */
@AndroidEntryPoint
class OpenPgpApiService : Service() {
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var apiAppDao: ApiAppDao
    @Inject lateinit var apiAllowedKeyDao: ApiAllowedKeyDao
    @Inject lateinit var userIdDao: UserIdDao
    @Inject lateinit var cryptoOperations: CryptoOperations
    @Inject lateinit var settingsRepository: SettingsRepository

    private val cryptoDispatcher = Dispatchers.Default
    private val outputPipes = ConcurrentHashMap<Int, ParcelFileDescriptor>()

    private val binder = object : IOpenPgpService2.Stub() {
        override fun createOutputPipe(pipeId: Int): ParcelFileDescriptor {
            val pipe = ParcelFileDescriptor.createPipe()
            outputPipes[pipeId] = pipe[1]
            return pipe[0]
        }

        override fun execute(data: Intent?, input: ParcelFileDescriptor?, pipeId: Int): Intent =
            runBlocking(cryptoDispatcher) {
                executeInternal(data ?: Intent(), input, pipeId)
            }
    }

    private suspend fun executeInternal(data: Intent, input: ParcelFileDescriptor?, pipeId: Int): Intent {
        val apiVersion = data.getIntExtra(OpenPgpConstants.EXTRA_API_VERSION, -1)
        if (apiVersion < 0) {
            return errorResult(OpenPgpError.INCOMPATIBLE_API_VERSIONS, "Missing api_version extra")
        }

        val callerPkg = callingPackage()
        val action = data.action ?: return errorResult(OpenPgpError.GENERIC_ERROR, "Missing action")

        if (action == OpenPgpConstants.ACTION_CHECK_PERMISSION) {
            return if (apiAppDao.get(callerPkg) != null) {
                successResult()
            } else {
                userInteractionResult(callerPkg)
            }
        }

        if (apiAppDao.get(callerPkg) == null) {
            return userInteractionResult(callerPkg)
        }

        val inputBytes = readInput(input)
        val (outputBytes, result) = when (action) {
            OpenPgpConstants.ACTION_ENCRYPT,
            OpenPgpConstants.ACTION_SIGN_AND_ENCRYPT,
            -> handleEncrypt(inputBytes, data, callerPkg, sign = action == OpenPgpConstants.ACTION_SIGN_AND_ENCRYPT)

            OpenPgpConstants.ACTION_DECRYPT_VERIFY -> handleDecryptVerify(inputBytes, data, callerPkg)

            OpenPgpConstants.ACTION_SIGN,
            OpenPgpConstants.ACTION_CLEARTEXT_SIGN,
            OpenPgpConstants.ACTION_DETACHED_SIGN,
            -> handleSign(inputBytes, data, callerPkg, detached = action == OpenPgpConstants.ACTION_DETACHED_SIGN)

            OpenPgpConstants.ACTION_GET_KEY_IDS -> handleGetKeyIds(data)

            OpenPgpConstants.ACTION_BACKUP -> handleBackup(data, callerPkg)

            else -> null to errorResult(OpenPgpError.GENERIC_ERROR, "Unsupported action: $action")
        }

        writeOutput(pipeId, outputBytes)
        return result
    }

    private suspend fun handleEncrypt(
        input: ByteArray,
        data: Intent,
        callerPkg: String,
        sign: Boolean,
    ): Pair<ByteArray?, Intent> {
        val publicKeys = resolveRecipientKeys(data, callerPkg)
        if (publicKeys.isEmpty()) {
            return null to errorResult(OpenPgpError.NO_USER_IDS, "No recipient keys found")
        }
        val asciiArmor = data.getBooleanExtra(OpenPgpConstants.EXTRA_REQUEST_ASCII_ARMOR, false)
        val fileName = data.getStringExtra(OpenPgpConstants.EXTRA_ORIGINAL_FILENAME) ?: "_CONSOLE"
        return try {
            var plaintext = input
            if (sign) {
                val signKeyId = resolveSignKeyId(data)
                val signed = signPayload(plaintext, data, callerPkg, signKeyId, detached = false)
                    ?: return null to userInteractionResult(callerPkg)
                plaintext = signed
            }
            val encrypted = cryptoOperations.encrypt(plaintext, publicKeys, asciiArmor, fileName)
            encrypted.ciphertext to successResult()
        } catch (e: Exception) {
            Timber.e(e, "OpenPGP encrypt failed")
            null to errorResult(OpenPgpError.GENERIC_ERROR, CryptoErrors.safeMessage(e, "Encryption failed"))
        }
    }

    private suspend fun handleDecryptVerify(
        input: ByteArray,
        data: Intent,
        callerPkg: String,
    ): Pair<ByteArray?, Intent> {
        val secretKeys = keyRepository.search("").filter { it.isSecret && isKeyAllowed(callerPkg, it.masterKeyId) }
        if (secretKeys.isEmpty()) {
            return null to errorResult(OpenPgpError.GENERIC_ERROR, "No secret keys available")
        }
        val requestedPass = data.getCharArrayExtra(OpenPgpConstants.EXTRA_PASSPHRASE)
            ?: return null to userInteractionResult(callerPkg)
        try {
            for (key in secretKeys) {
                val secret = keyRepository.getArmoredSecret(key.masterKeyId) ?: continue
                try {
                    val decrypted = cryptoOperations.decrypt(input, secret, requestedPass)
                    return decrypted.plaintext to successResult()
                } catch (_: Exception) {
                    continue
                }
            }
            return null to errorResult(OpenPgpError.NO_OR_WRONG_PASSPHRASE, "Decryption failed")
        } finally {
            requestedPass.fill('\u0000')
        }
    }

    private suspend fun handleSign(
        input: ByteArray,
        data: Intent,
        callerPkg: String,
        detached: Boolean,
    ): Pair<ByteArray?, Intent> {
        val signKeyId = resolveSignKeyId(data)
        if (!isKeyAllowed(callerPkg, signKeyId)) {
            return null to errorResult(OpenPgpError.GENERIC_ERROR, "Signing key not allowed")
        }
        try {
            val signed = signPayload(input, data, callerPkg, signKeyId, detached)
                ?: return null to userInteractionResult(callerPkg)
            return if (detached) {
                null to successResult().apply {
                    putExtra(OpenPgpConstants.RESULT_DETACHED_SIGNATURE, signed)
                    putExtra(OpenPgpConstants.RESULT_SIGNATURE_MICALG, "SHA256")
                }
            } else {
                signed to successResult()
            }
        } catch (e: Exception) {
            Timber.e(e, "OpenPGP sign failed")
            return null to errorResult(OpenPgpError.GENERIC_ERROR, CryptoErrors.safeMessage(e, "Signing failed"))
        }
    }

    private suspend fun signPayload(
        input: ByteArray,
        data: Intent,
        callerPkg: String,
        signKeyId: Long,
        detached: Boolean,
    ): ByteArray? {
        if (!isKeyAllowed(callerPkg, signKeyId)) return null
        val secret = keyRepository.getArmoredSecret(signKeyId) ?: return null
        val passphrase = data.getCharArrayExtra(OpenPgpConstants.EXTRA_PASSPHRASE) ?: return null
        return try {
            cryptoOperations.sign(input, secret, passphrase, detachedBinary = detached).output
        } finally {
            passphrase.fill('\u0000')
        }
    }

    private suspend fun handleGetKeyIds(data: Intent): Pair<ByteArray?, Intent> {
        val userIds = data.getStringArrayExtra(OpenPgpConstants.EXTRA_USER_IDS)
            ?: return null to errorResult(OpenPgpError.NO_USER_IDS, "Missing user_ids")
        val keyIds = LongArray(userIds.size) { index ->
            userIdDao.findByUserIdFragment(userIds[index]).firstOrNull()?.masterKeyId ?: 0L
        }
        return null to successResult().apply {
            putExtra(OpenPgpConstants.RESULT_KEY_IDS, keyIds)
        }
    }

    private suspend fun handleBackup(data: Intent, callerPkg: String): Pair<ByteArray?, Intent> {
        val keyIds = data.getLongArrayExtra(OpenPgpConstants.EXTRA_KEY_IDS)
            ?: return null to errorResult(OpenPgpError.GENERIC_ERROR, "Missing key_ids")
        val builder = StringBuilder()
        for (keyId in keyIds) {
            if (!isKeyAllowed(callerPkg, keyId)) continue
            val armored = keyRepository.getArmoredPublic(keyId) ?: keyRepository.exportKeyRing(keyId)
            builder.append(String(armored, Charsets.UTF_8))
            if (!builder.endsWith("\n")) builder.append('\n')
        }
        if (builder.isEmpty()) {
            return null to errorResult(OpenPgpError.GENERIC_ERROR, "No keys to export")
        }
        return builder.toString().toByteArray(Charsets.UTF_8) to successResult()
    }

    private suspend fun resolveRecipientKeys(data: Intent, callerPkg: String): List<ByteArray> {
        val byId = data.getLongArrayExtra(OpenPgpConstants.EXTRA_KEY_IDS)
        if (byId != null) {
            return byId.toList().mapNotNull { id ->
                if (!isKeyAllowed(callerPkg, id)) return@mapNotNull null
                keyRepository.getArmoredPublic(id)
            }
        }
        val userIds = data.getStringArrayExtra(OpenPgpConstants.EXTRA_USER_IDS) ?: return emptyList()
        return userIds.mapNotNull { uid ->
            val keyId = userIdDao.findByUserIdFragment(uid).firstOrNull()?.masterKeyId ?: return@mapNotNull null
            if (!isKeyAllowed(callerPkg, keyId)) return@mapNotNull null
            keyRepository.getArmoredPublic(keyId)
        }
    }

    private suspend fun resolveSignKeyId(data: Intent): Long {
        val explicit = data.getLongExtra(OpenPgpConstants.EXTRA_SIGN_KEY_ID, 0L)
        if (explicit != 0L) return explicit
        val settings = settingsRepository.current()
        settings.defaultSignKeyId?.let { return it }
        return keyRepository.observeKeys().first().firstOrNull { it.isSecret }?.masterKeyId ?: 0L
    }

    private suspend fun isKeyAllowed(packageName: String, keyId: Long): Boolean {
        if (keyId == 0L) return false
        val allowed = apiAllowedKeyDao.allowedKeyIds(packageName)
        return allowed.isEmpty() || keyId in allowed
    }

    private fun readInput(input: ParcelFileDescriptor?): ByteArray {
        if (input == null) return ByteArray(0)
        return ParcelFileDescriptor.AutoCloseInputStream(input).use { stream ->
            PgpIo.readLimited(stream)
        }
    }

    private fun writeOutput(pipeId: Int, bytes: ByteArray?) {
        val writeEnd = outputPipes.remove(pipeId) ?: return
        runCatching {
            if (bytes == null || bytes.isEmpty()) {
                writeEnd.close()
                return
            }
            ParcelFileDescriptor.AutoCloseOutputStream(writeEnd).use { it.write(bytes) }
        }.onFailure {
            Timber.w(it, "Failed writing OpenPGP pipe %s", pipeId)
            runCatching { writeEnd.close() }
        }
    }

    /** Closes any dangling output pipes when the service is torn down. */
    override fun onDestroy() {
        outputPipes.values.forEach { pipe -> runCatching { pipe.close() } }
        outputPipes.clear()
        super.onDestroy()
    }

    /** Returns the OpenPGP API binder to connecting clients. */
    override fun onBind(intent: Intent?): IBinder = binder

    private fun callingPackage(): String {
        val uid = Binder.getCallingUid()
        @Suppress("DEPRECATION")
        val packages = packageManager.getPackagesForUid(uid) ?: emptyArray()
        return packages.firstOrNull() ?: throw SecurityException("Unknown caller")
    }

    private fun successResult(): Intent = Intent().apply {
        putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_SUCCESS)
    }

    private fun errorResult(errorId: Int, message: String): Intent = Intent().apply {
        putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_ERROR)
        putExtra(OpenPgpConstants.RESULT_ERROR, OpenPgpError(errorId, message))
    }

    private fun userInteractionResult(packageName: String): Intent {
        val grant = Intent(this, GrantApiAccessActivity::class.java).apply {
            putExtra(GrantApiAccessActivity.EXTRA_PACKAGE, packageName)
        }
        val pending = PendingIntent.getActivity(
            this,
            packageName.hashCode(),
            grant,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Intent().apply {
            putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpConstants.RESULT_INTENT, pending)
        }
    }
}
