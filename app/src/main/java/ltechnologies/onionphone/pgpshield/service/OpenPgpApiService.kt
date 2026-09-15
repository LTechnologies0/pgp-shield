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
import android.os.Message
import android.os.Messenger
import android.os.ParcelFileDescriptor
import android.os.RemoteException
import dagger.hilt.android.AndroidEntryPoint
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.api.ApiAutocryptSetupCodeActivity
import ltechnologies.onionphone.pgpshield.api.ApiGrantKeyPermissionActivity
import ltechnologies.onionphone.pgpshield.api.ApiInsecureCryptoActivity
import ltechnologies.onionphone.pgpshield.api.ApiPassphraseActivity
import ltechnologies.onionphone.pgpshield.api.ApiSelectEncryptKeyActivity
import ltechnologies.onionphone.pgpshield.api.ApiSelectSignKeyActivity
import ltechnologies.onionphone.pgpshield.api.ApiUnlockActivity
import ltechnologies.onionphone.pgpshield.api.GrantApiAccessActivity
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.AutocryptManager
import ltechnologies.onionphone.pgpshield.data.CryptoWarningOverrideStore
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeySummary
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.data.db.ApiAllowedKeyDao
import ltechnologies.onionphone.pgpshield.data.db.ApiAppDao
import ltechnologies.onionphone.pgpshield.data.db.UserIdDao
import ltechnologies.onionphone.pgpshield.engine.ArmorHeaders
import ltechnologies.onionphone.pgpshield.engine.KeyRingMinimizer
import ltechnologies.onionphone.pgpshield.engine.KeyRingReader
import ltechnologies.onionphone.pgpshield.engine.MessageCompression
import ltechnologies.onionphone.pgpshield.engine.MessageIntegrity
import ltechnologies.onionphone.pgpshield.engine.InteropProfile
import ltechnologies.onionphone.pgpshield.engine.PgpAlgorithmPolicy
import ltechnologies.onionphone.pgpshield.engine.PgpException
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import ltechnologies.onionphone.pgpshield.engine.PgpStreams
import ltechnologies.onionphone.pgpshield.engine.SecurityProblem
import ltechnologies.onionphone.pgpshield.engine.SignResult
import ltechnologies.onionphone.pgpshield.intent.ImportKeyActivity
import ltechnologies.onionphone.pgpshield.intent.PgpIntentActions
import ltechnologies.onionphone.pgpshield.openpgp.OpenPgpConstants
import ltechnologies.onionphone.pgpshield.ui.MainActivity
import ltechnologies.onionphone.pgpshield.security.AppLockManager
import ltechnologies.onionphone.pgpshield.security.AppLockState
import ltechnologies.onionphone.pgpshield.util.CryptoErrors
import java.security.SecureRandom
import java.util.Arrays
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.openintents.openpgp.AutocryptPeerUpdate
import org.openintents.openpgp.IOpenPgpService2
import org.openintents.openpgp.OpenPgpDecryptionResult
import org.openintents.openpgp.OpenPgpError
import org.openintents.openpgp.OpenPgpMetadata
import org.openintents.openpgp.OpenPgpSignatureResult
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
    @Inject lateinit var settingsRepository: SettingsRepository
    @Inject lateinit var userIdDao: UserIdDao
    @Inject lateinit var cryptoOperations: CryptoOperations
    @Inject lateinit var appLockManager: AppLockManager
    @Inject lateinit var autocryptManager: AutocryptManager
    @Inject lateinit var cryptoWarningOverrideStore: CryptoWarningOverrideStore

    private val cryptoDispatcher = Dispatchers.Default
    private val outputPipes = ConcurrentHashMap<Int, ParcelFileDescriptor>()

    private fun requireVaultUnlocked() {
        if (appLockManager.state.value != AppLockState.UNLOCKED) {
            error(getString(R.string.api_err_locked))
        }
    }

    /** OpenKeychain-style unlock PendingIntent when the vault is not [AppLockState.UNLOCKED]. */
    private fun unlockInteractionOrNull(packageName: String): Intent? {
        if (appLockManager.state.value == AppLockState.UNLOCKED) return null
        return unlockInteractionResult(packageName)
    }

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
            return errorResult(OpenPgpError.INCOMPATIBLE_API_VERSIONS, getString(R.string.api_err_missing_api_version))
        }

        val callerPkg = callingPackage()
        val action = data.action ?: return errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_missing_action))

        if (action == OpenPgpConstants.ACTION_CHECK_PERMISSION) {
            return if (apiAppDao.get(callerPkg) != null) {
                // Advertise override-crypto support so K-9 / FairEmail enable their UX path.
                successResult().apply {
                    putExtra(OpenPgpConstants.EXTRA_SUPPORT_OVERRIDE_CRYPTO_WARNING, true)
                }
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

            // ACTION_SIGN is treated as cleartext sign (OpenKeychain / API v11 convention).
            OpenPgpConstants.ACTION_SIGN,
            OpenPgpConstants.ACTION_CLEARTEXT_SIGN,
            -> handleSign(inputBytes, data, callerPkg, detached = false)

            OpenPgpConstants.ACTION_DETACHED_SIGN,
            -> handleSign(inputBytes, data, callerPkg, detached = true)

            OpenPgpConstants.ACTION_GET_KEY_IDS -> handleGetKeyIds(data, callerPkg)

            OpenPgpConstants.ACTION_GET_KEY -> handleGetKey(data, callerPkg)

            OpenPgpConstants.ACTION_GET_SIGN_KEY_ID,
            OpenPgpConstants.ACTION_GET_SIGN_KEY_ID_LEGACY,
            -> handleGetSignKeyId(data, callerPkg)

            OpenPgpConstants.ACTION_DECRYPT_METADATA -> handleDecryptMetadata(inputBytes, data, callerPkg)

            OpenPgpConstants.ACTION_BACKUP -> handleBackup(data, callerPkg)

            OpenPgpConstants.ACTION_QUERY_AUTOCRYPT_STATUS -> handleQueryAutocryptStatus(data)

            OpenPgpConstants.ACTION_UPDATE_AUTOCRYPT_PEER -> handleUpdateAutocryptPeer(data)

            OpenPgpConstants.ACTION_AUTOCRYPT_KEY_TRANSFER -> handleAutocryptKeyTransfer(data, callerPkg)

            else -> null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_unsupported_action_fmt, action))
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
        when (val resolution = resolveRecipientKeys(data, callerPkg)) {
            is RecipientResolution.NeedPicker ->
                return null to encryptKeyInteractionResult(callerPkg, data)
            is RecipientResolution.MissingRecipient ->
                return null to Intent().apply {
                    putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
                    putExtra(
                        OpenPgpConstants.RESULT_INTENT,
                        importMissingByQueryPendingIntent(resolution.userId),
                    )
                }
            is RecipientResolution.KeyPermissionNeeded ->
                return null to keyPermissionInteractionResult(callerPkg, resolution.masterKeyIds)
            is RecipientResolution.OpportunisticMissing ->
                return null to errorResult(
                    OpenPgpError.OPPORTUNISTIC_MISSING_KEYS,
                    getString(R.string.api_err_opportunistic_missing_keys),
                )
            is RecipientResolution.Failed ->
                return null to errorResult(OpenPgpError.NO_USER_IDS, getString(R.string.api_err_unresolved_recipients))
            is RecipientResolution.Ok -> {
                val publicKeys = resolution.keys
                if (publicKeys.isEmpty()) {
                    return null to errorResult(OpenPgpError.NO_USER_IDS, getString(R.string.api_err_no_recipients))
                }
                // openpgp-api / OpenKeychain: EXTRA_REQUEST_ASCII_ARMOR defaults to true for encrypt.
                val asciiArmor = data.getBooleanExtra(OpenPgpConstants.EXTRA_REQUEST_ASCII_ARMOR, true)
                val customHeaders = ArmorHeaders.fromHeaderLines(
                    data.getStringArrayListExtra(OpenPgpConstants.EXTRA_CUSTOM_HEADERS),
                )
                val fileName = data.getStringExtra(OpenPgpConstants.EXTRA_ORIGINAL_FILENAME) ?: "_CONSOLE"
                // openpgp-api: EXTRA_ENABLE_COMPRESSION defaults to true.
                val compression = if (data.getBooleanExtra(OpenPgpConstants.EXTRA_ENABLE_COMPRESSION, true)) {
                    MessageCompression.ZLIB
                } else {
                    MessageCompression.NONE
                }
                return try {
                    var signSecret: ByteArray? = null
                    var signPass: CharArray? = null
                    try {
                        var recipients = publicKeys
                        if (sign) {
                            val signKeyId = resolveSignKeyId(data)
                            if (signKeyId == 0L) {
                                return null to signKeyPickerFromRequest(callerPkg, data)
                            }
                            if (!isKeyAllowed(callerPkg, signKeyId)) {
                                return null to keyPermissionInteractionResult(
                                    callerPkg,
                                    longArrayOf(findSignerSummary(signKeyId)?.masterKeyId ?: signKeyId),
                                )
                            }
                            unlockInteractionOrNull(callerPkg)?.let { return null to it }
                            signPass = data.getCharArrayExtra(OpenPgpConstants.EXTRA_PASSPHRASE)
                                ?: return null to passphraseInteractionResult(callerPkg)
                            signSecret = keyRepository.getArmoredSecret(
                                findSignerSummary(signKeyId)?.masterKeyId ?: signKeyId,
                            )
                                ?: return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_signing_key_not_found))
                            // OpenKeychain setAdditionalEncryptId: encrypt-to-self so Sent/Drafts reopen.
                            recipients = withEncryptToSelf(recipients, signKeyId)
                        }
                        val integrity = InteropProfile.fromName(settingsRepository.current().interopProfile)
                            .defaultIntegrity()
                        val encrypted = cryptoOperations.encrypt(
                            plaintext = input,
                            recipientPublicArmored = recipients,
                            asciiArmor = asciiArmor,
                            fileName = fileName,
                            compression = compression,
                            integrity = integrity,
                            // Mail clients / OpenKeychain keys rarely advertise SEIPDv2 — negotiate MDC.
                            allowMdcDegrade = true,
                            signSecretArmored = signSecret,
                            signPassphrase = signPass,
                            customArmorHeaders = customHeaders,
                        )
                        encrypted.ciphertext to successResult()
                    } finally {
                        signPass?.fill('\u0000')
                    }
                } catch (e: Exception) {
                    Timber.e(e, "OpenPGP encrypt failed")
                    null to errorResult(OpenPgpError.GENERIC_ERROR, CryptoErrors.safeMessage(e, getString(R.string.api_err_encryption_failed)))
                }
            }
        }
    }

    private suspend fun handleDecryptVerify(
        input: ByteArray,
        data: Intent,
        callerPkg: String,
    ): Pair<ByteArray?, Intent> {
        val senderAddress = data.getStringExtra(OpenPgpConstants.EXTRA_SENDER_ADDRESS)
        val supportOverride = data.getBooleanExtra(
            OpenPgpConstants.EXTRA_SUPPORT_OVERRIDE_CRYPTO_WARNING,
            false,
        )
        val autocryptPeerResult = ingestAutocryptPeerExtras(data)
        val progress = progressReporter(data)
        progress(0, 100)
        val detachedSig = data.getByteArrayExtra(OpenPgpConstants.EXTRA_DETACHED_SIGNATURE)
        if (detachedSig != null) {
            val out = handleDetachedVerify(
                input, detachedSig, callerPkg, senderAddress, autocryptPeerResult, supportOverride,
            )
            progress(100, 100)
            return out
        }
        if (looksLikeCleartextSigned(input)) {
            val out = handleCleartextVerify(
                input, callerPkg, senderAddress, autocryptPeerResult, supportOverride,
            )
            progress(100, 100)
            return out
        }

        @Suppress("DEPRECATION")
        val cachedDecryption = data.getParcelableExtra<OpenPgpDecryptionResult>(
            OpenPgpConstants.EXTRA_DECRYPTION_RESULT,
        )
        val cachedSession = cachedDecryption
            ?.takeIf { it.hasDecryptedSessionKey() }
            ?.getDecryptedSessionKey()

        // Include all local pubs for crypto verify; allowlist gates the result (grant PI), not the ring.
        val signerPubs = keyRepository.search("").mapNotNull { summary ->
            keyRepository.getArmoredPublic(summary.masterKeyId)
        }

        if (cachedSession != null) {
            try {
                progress(40, 100)
                val decrypted = cryptoOperations.decryptWithSessionKey(
                    ciphertext = input,
                    decryptedSessionKey = cachedSession,
                    signerPublicArmored = signerPubs,
                )
                    progress(100, 100)
                    signerAllowlistInteractionOrNull(callerPkg, decrypted.signerKeyId)?.let {
                        return null to it
                    }
                    return decrypted.plaintext to decryptSuccessIntent(
                        decrypted = decrypted,
                        input = input,
                        senderAddress = senderAddress,
                        autocryptPeerResult = autocryptPeerResult,
                        // Preserve the client's cache markers when reusing.
                        sessionKey = cachedDecryption.getSessionKey(),
                        decryptedSessionKey = cachedSession,
                        supportOverrideCryptoWarning = supportOverride,
                    )
            } catch (e: Exception) {
                Timber.d(e, "Cached session-key decrypt failed; falling back to passphrase")
            }
        }

        val allSecrets = keyRepository.search("").filter { it.isSecret }
        if (allSecrets.isEmpty()) {
            return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_no_secret_keys))
        }
        val secretKeys = allSecrets.filter { isKeyAllowed(callerPkg, it.masterKeyId) }

        // Preflight: PKESK-only — distinguish missing vs local-but-disallowed (OKC key permission).
        val encryptedInfo = runCatching { PgpStreams.inspectEncryptedRecipients(input) }.getOrNull()
        if (encryptedInfo != null &&
            !encryptedInfo.hasPassphraseSession &&
            encryptedInfo.pkeskKeyIds.isNotEmpty()
        ) {
            val allLocalIds = collectLocalSecretKeyIds(allSecrets)
            val pkeskOnDevice = encryptedInfo.pkeskKeyIds.any { it in allLocalIds }
            if (!pkeskOnDevice) {
                return null to errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    getString(R.string.api_err_no_matching_secret),
                )
            }
            val allowedLocalIds = collectLocalSecretKeyIds(secretKeys)
            val pkeskAllowed = encryptedInfo.pkeskKeyIds.any { it in allowedLocalIds }
            if (!pkeskAllowed) {
                val neededMasters = disallowedMastersForPkesk(callerPkg, allSecrets, encryptedInfo.pkeskKeyIds)
                if (neededMasters.isNotEmpty()) {
                    return null to keyPermissionInteractionResult(callerPkg, neededMasters)
                }
                return null to errorResult(
                    OpenPgpError.GENERIC_ERROR,
                    getString(R.string.api_err_no_matching_secret),
                )
            }
        }

        if (secretKeys.isEmpty()) {
            // Secrets exist but none allowlisted for this caller — grant PI (OKC), not "no keys".
            return null to keyPermissionInteractionResult(
                callerPkg,
                allSecrets.map { it.masterKeyId }.distinct().toLongArray(),
            )
        }

        unlockInteractionOrNull(callerPkg)?.let { return null to it }
        val requestedPass = data.getCharArrayExtra(OpenPgpConstants.EXTRA_PASSPHRASE)
            ?: return null to passphraseInteractionResult(callerPkg)
        try {
            progress(10, 100)
            val secrets = coroutineScope {
                secretKeys.map { key ->
                    async(Dispatchers.IO) {
                        key.masterKeyId to (keyRepository.getArmoredSecret(key.masterKeyId) ?: return@async null)
                    }
                }.mapNotNull { it.await() }
            }
            progress(25, 100)
            for ((_, secret) in secrets) {
                try {
                    progress(40, 100)
                    val decrypted = cryptoOperations.decrypt(
                        input,
                        secret,
                        requestedPass,
                        signerPublicArmored = signerPubs,
                    )
                    progress(100, 100)
                    signerAllowlistInteractionOrNull(callerPkg, decrypted.signerKeyId)?.let {
                        return null to it
                    }
                    return decrypted.plaintext to decryptSuccessIntent(
                        decrypted = decrypted,
                        input = input,
                        senderAddress = senderAddress,
                        autocryptPeerResult = autocryptPeerResult,
                        sessionKey = decrypted.sessionKey,
                        decryptedSessionKey = decrypted.decryptedSessionKey,
                        supportOverrideCryptoWarning = supportOverride,
                    )
                } catch (_: Exception) {
                    continue
                }
            }
            return null to errorResult(OpenPgpError.NO_OR_WRONG_PASSPHRASE, getString(R.string.api_err_decryption_failed))
        } finally {
            requestedPass.fill('\u0000')
        }
    }

    private suspend fun decryptSuccessIntent(
        decrypted: ltechnologies.onionphone.pgpshield.engine.DecryptResult,
        input: ByteArray,
        senderAddress: String?,
        autocryptPeerResult: OpenPgpSignatureResult.AutocryptPeerResult?,
        sessionKey: ByteArray?,
        decryptedSessionKey: ByteArray?,
        supportOverrideCryptoWarning: Boolean = false,
    ): Intent {
        val result = successResult()
        decrypted.signerKeyId?.let {
            result.putExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, it)
        }
        decrypted.signatureValid?.let {
            result.putExtra(OpenPgpConstants.RESULT_SIGNATURE_VERIFIED, it)
        }
        val fileName = decrypted.fileName ?: "_CONSOLE"
        result.putExtra(OpenPgpConstants.EXTRA_ORIGINAL_FILENAME, fileName)
        val charset = armorCharsetOrNull(input)
        val insecureDecrypt = decrypted.securityProblems.isNotEmpty()
        val decryptionStatus = if (insecureDecrypt) {
            OpenPgpDecryptionResult.RESULT_INSECURE
        } else {
            OpenPgpDecryptionResult.RESULT_ENCRYPTED
        }
        val decryption = if (sessionKey != null && decryptedSessionKey != null) {
            OpenPgpDecryptionResult(decryptionStatus, sessionKey, decryptedSessionKey)
        } else {
            OpenPgpDecryptionResult(decryptionStatus)
        }
        putDecryptVerifyParcelables(
            result = result,
            signature = signatureResultFromDecrypt(
                signatureValid = decrypted.signatureValid,
                signerKeyId = decrypted.signerKeyId,
                senderAddress = senderAddress,
                autocryptPeerResult = autocryptPeerResult,
                signatureTimestampMs = decrypted.signatureTimestampMs,
            ),
            decryption = decryption,
            metadata = OpenPgpMetadata(
                filename = fileName,
                mimeType = decrypted.mimeType,
                modificationTime = decrypted.modificationTimeMs,
                originalSize = decrypted.plaintext.size.toLong(),
                charset = charset,
            ),
            insecureDetail = if (insecureDecrypt) {
                getString(R.string.api_insecure_crypto_body)
            } else {
                null
            },
            supportOverrideCryptoWarning = supportOverrideCryptoWarning,
        )
        return result
    }

    private fun looksLikeCleartextSigned(input: ByteArray): Boolean {
        if (input.isEmpty()) return false
        val n = minOf(input.size, 96)
        val head = String(input, 0, n, Charsets.UTF_8)
        return head.contains("BEGIN PGP SIGNED MESSAGE")
    }

    /**
     * OpenKeychain DECRYPT_VERIFY for clearsigned mail (`BEGIN PGP SIGNED MESSAGE`):
     * verify only — no passphrase / decrypt.
     */
    private suspend fun handleCleartextVerify(
        input: ByteArray,
        callerPkg: String,
        senderAddress: String?,
        autocryptPeerResult: OpenPgpSignatureResult.AutocryptPeerResult? = null,
        supportOverrideCryptoWarning: Boolean = false,
    ): Pair<ByteArray?, Intent> {
        val signerPubs = keyRepository.search("").mapNotNull { summary ->
            keyRepository.getArmoredPublic(summary.masterKeyId)
        }
        return try {
            val verified = cryptoOperations.verify(
                signedData = input,
                publicArmored = signerPubs,
            )
            verified.signerKeyId?.let { sid ->
                signerAllowlistInteractionOrNull(callerPkg, sid)?.let { return null to it }
            }
            val signature = when {
                verified.valid && verified.signerKeyId != null ->
                    enrichValidSignatureResult(verified.signerKeyId!!, senderAddress, autocryptPeerResult)
                verified.signerKeyId != null &&
                    (
                        verified.error?.contains("not in keyring", ignoreCase = true) == true ||
                            findSignerSummary(verified.signerKeyId!!) == null
                        ) ->
                    OpenPgpSignatureResult.createWithKeyMissing(verified.signerKeyId!!)
                else -> OpenPgpSignatureResult.createWithInvalidSignature()
            }
            val plaintext = verified.message ?: input
            val charset = armorCharsetOrNull(input)
            val result = successResult().apply {
                verified.signerKeyId?.let { putExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, it) }
                putExtra(OpenPgpConstants.RESULT_SIGNATURE_VERIFIED, verified.valid)
                putExtra(OpenPgpConstants.EXTRA_ORIGINAL_FILENAME, "_CONSOLE")
                putDecryptVerifyParcelables(
                    result = this,
                    signature = signature,
                    decryption = OpenPgpDecryptionResult(OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED),
                    metadata = OpenPgpMetadata(
                        filename = "_CONSOLE",
                        mimeType = "text/plain",
                        modificationTime = 0L,
                        originalSize = plaintext.size.toLong(),
                        charset = charset,
                    ),
                    supportOverrideCryptoWarning = supportOverrideCryptoWarning,
                )
            }
            plaintext to result
        } catch (e: Exception) {
            Timber.e(e, "OpenPGP cleartext verify failed")
            null to errorResult(
                OpenPgpError.GENERIC_ERROR,
                CryptoErrors.safeMessage(e, getString(R.string.api_err_decryption_failed)),
            )
        }
    }

    /**
     * OpenKeychain DECRYPT_VERIFY with [OpenPgpConstants.EXTRA_DETACHED_SIGNATURE]:
     * treat [input] as plaintext and verify the detached signature (no decrypt / passphrase).
     */
    private suspend fun handleDetachedVerify(
        input: ByteArray,
        detachedSignature: ByteArray,
        callerPkg: String,
        senderAddress: String?,
        autocryptPeerResult: OpenPgpSignatureResult.AutocryptPeerResult? = null,
        supportOverrideCryptoWarning: Boolean = false,
    ): Pair<ByteArray?, Intent> {
        val signerPubs = keyRepository.search("").mapNotNull { summary ->
            keyRepository.getArmoredPublic(summary.masterKeyId)
        }
        return try {
            // Empty local keyring is OK — verify still parses signer key id for KEY_MISSING + import PI.
            val verified = cryptoOperations.verify(
                signedData = detachedSignature,
                publicArmored = signerPubs,
                message = input,
                binaryDocument = true,
            )
            verified.signerKeyId?.let { sid ->
                signerAllowlistInteractionOrNull(callerPkg, sid)?.let { return null to it }
            }
            val signature = when {
                verified.valid && verified.signerKeyId != null ->
                    enrichValidSignatureResult(verified.signerKeyId!!, senderAddress, autocryptPeerResult)
                verified.signerKeyId != null &&
                    (
                        verified.error?.contains("not in keyring", ignoreCase = true) == true ||
                            findSignerSummary(verified.signerKeyId!!) == null
                        ) ->
                    OpenPgpSignatureResult.createWithKeyMissing(verified.signerKeyId!!)
                else -> OpenPgpSignatureResult.createWithInvalidSignature()
            }
            val result = successResult().apply {
                verified.signerKeyId?.let { putExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, it) }
                putExtra(OpenPgpConstants.RESULT_SIGNATURE_VERIFIED, verified.valid)
                putExtra(OpenPgpConstants.EXTRA_ORIGINAL_FILENAME, "_CONSOLE")
                putDecryptVerifyParcelables(
                    result = this,
                    signature = signature,
                    decryption = OpenPgpDecryptionResult(OpenPgpDecryptionResult.RESULT_NOT_ENCRYPTED),
                    metadata = OpenPgpMetadata(
                        filename = "_CONSOLE",
                        mimeType = null,
                        modificationTime = 0L,
                        originalSize = input.size.toLong(),
                    ),
                    supportOverrideCryptoWarning = supportOverrideCryptoWarning,
                )
            }
            // Return plaintext so clients that supply an output pipe receive the verified message.
            input to result
        } catch (e: Exception) {
            Timber.e(e, "OpenPGP detached verify failed")
            null to errorResult(
                OpenPgpError.GENERIC_ERROR,
                CryptoErrors.safeMessage(e, getString(R.string.api_err_decryption_failed)),
            )
        }
    }

    private suspend fun signatureResultFromDecrypt(
        signatureValid: Boolean?,
        signerKeyId: Long?,
        senderAddress: String?,
        autocryptPeerResult: OpenPgpSignatureResult.AutocryptPeerResult? = null,
        signatureTimestampMs: Long? = null,
    ): OpenPgpSignatureResult = when {
        signatureValid == null -> OpenPgpSignatureResult.createWithNoSignature()
        signatureValid && signerKeyId != null ->
            enrichValidSignatureResult(
                signerKeyId,
                senderAddress,
                autocryptPeerResult,
                signatureTimestampMs,
            )
        signatureValid -> OpenPgpSignatureResult.createWithValidSignature(0L)
        // Encrypt+sign mail: missing local signer → KEY_MISSING + import PI (same as cleartext/detached).
        signerKeyId != null && findSignerSummary(signerKeyId) == null ->
            OpenPgpSignatureResult.createWithKeyMissing(signerKeyId)
        else -> OpenPgpSignatureResult.createWithInvalidSignature()
    }

    /**
     * Maps a cryptographically valid signature onto OKC-compatible trust/UID/revoked/expired
     * status so mail clients can show "signed by …" and confirmed/unconfirmed correctly.
     * When [senderAddress] is set (mail From:), [SenderStatusResult] reflects UID match.
     */
    private suspend fun enrichValidSignatureResult(
        signerKeyId: Long,
        senderAddress: String? = null,
        autocryptPeerResult: OpenPgpSignatureResult.AutocryptPeerResult? = null,
        signatureTimestampMs: Long? = null,
    ): OpenPgpSignatureResult {
        val stamp = signatureTimestampMs?.takeIf { it > 0L }?.let { java.util.Date(it) }
        val summary = findSignerSummary(signerKeyId)
            ?: return OpenPgpSignatureResult.createWithValidSignature(
                keyId = signerKeyId,
                autocryptPeerResult = autocryptPeerResult,
                signatureTimestamp = stamp,
            )
        val uid = summary.primaryUserId
        val userIds = userIdDao.forKey(summary.masterKeyId).map { it.userId }.ifEmpty {
            uid?.let { listOf(it) }.orEmpty()
        }
        val confirmed = summary.trustLevel == KeySummary.TRUST_FULL
        val senderStatus = senderStatusForAddress(senderAddress, userIds, confirmed)
        return when {
            summary.isRevoked ->
                OpenPgpSignatureResult.createWithRevokedKey(signerKeyId, uid)
            summary.isExpired ->
                OpenPgpSignatureResult.createWithExpiredKey(signerKeyId, uid)
            isSignerKeyInsecure(summary.masterKeyId) ->
                OpenPgpSignatureResult.createWithInsecureKey(signerKeyId, uid)
            // Mail From: present but not on signer UIDs → OKC result code 7 (not "valid").
            normalizeEmail(senderAddress) != null &&
                senderStatus == OpenPgpSignatureResult.SenderStatusResult.USER_ID_MISSING ->
                OpenPgpSignatureResult.createWithNotIntendedRecipient(
                    keyId = signerKeyId,
                    primaryUserId = uid,
                    userIds = userIds,
                    signatureTimestamp = stamp,
                    autocryptPeerResult = autocryptPeerResult,
                )
            else -> OpenPgpSignatureResult.createWithValidSignature(
                keyId = signerKeyId,
                confirmed = confirmed,
                primaryUserId = uid,
                userIds = userIds,
                senderStatusResult = senderStatus,
                autocryptPeerResult = autocryptPeerResult,
                signatureTimestamp = stamp,
            )
        }
    }

    /** True when the stored public ring fails algorithm policy (weak RSA, etc.). */
    private suspend fun isSignerKeyInsecure(masterKeyId: Long): Boolean {
        val armored = keyRepository.getArmoredPublic(masterKeyId) ?: return false
        return try {
            val info = KeyRingReader().readPublicKeyRing(armored.inputStream())
            PgpAlgorithmPolicy.validateKeyRing(info, allowRevoked = true, allowExpired = true)
            false
        } catch (e: PgpException) {
            e.securityProblem == SecurityProblem.INSECURE_ALGORITHM
        } catch (_: Exception) {
            false
        }
    }

    /**
     * Matches mail [senderAddress] against certificate UIDs (openpgp-api EXTRA_SENDER_ADDRESS).
     * Without a sender address, falls back to trust/UID presence.
     */
    private fun senderStatusForAddress(
        senderAddress: String?,
        userIds: List<String>,
        trustConfirmed: Boolean,
    ): OpenPgpSignatureResult.SenderStatusResult {
        val wanted = normalizeEmail(senderAddress)
        if (wanted == null) {
            return when {
                userIds.isEmpty() -> OpenPgpSignatureResult.SenderStatusResult.USER_ID_MISSING
                trustConfirmed -> OpenPgpSignatureResult.SenderStatusResult.USER_ID_CONFIRMED
                else -> OpenPgpSignatureResult.SenderStatusResult.USER_ID_UNCONFIRMED
            }
        }
        val matches = userIds.any { normalizeEmail(it) == wanted }
        return when {
            !matches -> OpenPgpSignatureResult.SenderStatusResult.USER_ID_MISSING
            trustConfirmed -> OpenPgpSignatureResult.SenderStatusResult.USER_ID_CONFIRMED
            else -> OpenPgpSignatureResult.SenderStatusResult.USER_ID_UNCONFIRMED
        }
    }

    private fun normalizeEmail(raw: String?): String? {
        if (raw.isNullOrBlank()) return null
        val trimmed = raw.trim()
        val fromAngles = trimmed.substringAfter('<', missingDelimiterValue = "")
            .substringBefore('>', missingDelimiterValue = "")
            .trim()
        val email = (fromAngles.ifBlank { trimmed }).lowercase()
        return email.takeIf { it.contains('@') }
    }

    /** Resolves master or signing-subkey [keyId] to the stored [KeySummary]. */
    private suspend fun findSignerSummary(keyId: Long): KeySummary? {
        keyRepository.getKeyDetail(keyId)?.summary?.let { return it }
        for (candidate in keyRepository.search("")) {
            if (candidate.masterKeyId == keyId) return candidate
            val detail = keyRepository.getKeyDetail(candidate.masterKeyId) ?: continue
            if (detail.subkeys.any { it.keyId == keyId }) return detail.summary
        }
        return null
    }

    private suspend fun putDecryptVerifyParcelables(
        result: Intent,
        signature: OpenPgpSignatureResult,
        decryption: OpenPgpDecryptionResult,
        metadata: OpenPgpMetadata,
        insecureDetail: String? = null,
        supportOverrideCryptoWarning: Boolean = false,
    ) {
        result.putExtra(OpenPgpConstants.RESULT_SIGNATURE, signature)
        result.putExtra(OpenPgpConstants.RESULT_DECRYPTION, decryption)
        result.putExtra(OpenPgpConstants.RESULT_METADATA, metadata)
        metadata.charset?.let { result.putExtra(OpenPgpConstants.RESULT_CHARSET, it) }
        attachSignatureResultIntent(result, signature)
        val insecureMessage = insecureDetail
            ?: if (signature.getResult() == OpenPgpSignatureResult.RESULT_INVALID_KEY_INSECURE) {
                getString(R.string.api_insecure_crypto_signer)
            } else if (decryption.getResult() == OpenPgpDecryptionResult.RESULT_INSECURE) {
                getString(R.string.api_insecure_crypto_body)
            } else {
                null
            }
        if (insecureMessage != null) {
            val problemId = insecureProblemId(signature, decryption)
            result.putExtra(
                OpenPgpConstants.RESULT_INSECURE_DETAIL_INTENT,
                insecureDetailPendingIntent(insecureMessage, problemId),
            )
            // OpenKeychain: boolean whether the warning was already overridden for this problem.
            if (supportOverrideCryptoWarning) {
                result.putExtra(
                    OpenPgpConstants.RESULT_OVERRIDE_CRYPTO_WARNING,
                    cryptoWarningOverrideStore.isOverridden(problemId),
                )
            }
        }
    }

    private fun insecureProblemId(
        signature: OpenPgpSignatureResult,
        decryption: OpenPgpDecryptionResult,
    ): String = when {
        signature.getResult() == OpenPgpSignatureResult.RESULT_INVALID_KEY_INSECURE ->
            "signer_insecure:${signature.getKeyId()}"
        decryption.getResult() == OpenPgpDecryptionResult.RESULT_INSECURE ->
            "body_insecure"
        else -> "insecure_generic"
    }

    /**
     * OpenKeychain: KEY_MISSING → import-from-keyserver PendingIntent;
     * known signer statuses → view-key PendingIntent for mail “Import key” / “View signer”.
     * View uses master key id when the signature key id is a signing subkey.
     */
    private suspend fun attachSignatureResultIntent(result: Intent, signature: OpenPgpSignatureResult) {
        val keyId = signature.getKeyId()
        if (keyId == 0L) return
        val pending = when (signature.getResult()) {
            OpenPgpSignatureResult.RESULT_KEY_MISSING ->
                importMissingSignerPendingIntent(keyId)
            OpenPgpSignatureResult.RESULT_VALID_KEY_CONFIRMED,
            OpenPgpSignatureResult.RESULT_VALID_KEY_UNCONFIRMED,
            OpenPgpSignatureResult.RESULT_INVALID_KEY_REVOKED,
            OpenPgpSignatureResult.RESULT_INVALID_KEY_EXPIRED,
            OpenPgpSignatureResult.RESULT_INVALID_KEY_INSECURE,
            OpenPgpSignatureResult.RESULT_INVALID_NOT_INTENDED_RECIPIENT,
            -> {
                val masterId = findSignerSummary(keyId)?.masterKeyId ?: keyId
                viewSignerPendingIntent(masterId)
            }
            else -> null
        } ?: return
        result.putExtra(OpenPgpConstants.RESULT_INTENT, pending)
    }

    private fun importMissingSignerPendingIntent(keyId: Long): PendingIntent {
        val importIntent = Intent(this, ImportKeyActivity::class.java).apply {
            action = PgpIntentActions.OKC_IMPORT_KEY_FROM_KEYSERVER
            putExtra(PgpIntentActions.OKC_EXTRA_KEY_ID, keyId)
        }
        return PendingIntent.getActivity(
            this,
            (keyId xor 0x1A2B_3C4D).toInt(),
            importIntent,
            apiInteractionPiFlags(),
        )
    }

    private fun importMissingByQueryPendingIntent(query: String): PendingIntent {
        val importIntent = Intent(this, ImportKeyActivity::class.java).apply {
            action = PgpIntentActions.OKC_IMPORT_KEY_FROM_KEYSERVER
            putExtra(PgpIntentActions.OKC_EXTRA_QUERY, query)
        }
        return PendingIntent.getActivity(
            this,
            query.hashCode() xor 0x7E11_0A11,
            importIntent,
            apiInteractionPiFlags(),
        )
    }

    private fun viewSignerPendingIntent(keyId: Long): PendingIntent {
        val view = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP
            putExtra(MainActivity.EXTRA_VIEW_KEY_ID, keyId)
        }
        return PendingIntent.getActivity(
            this,
            (keyId xor 0x5E6F_7081).toInt(),
            view,
            apiInteractionPiFlags(),
        )
    }

    private fun insecureDetailPendingIntent(detail: String, problemId: String): PendingIntent {
        val intent = Intent(this, ApiInsecureCryptoActivity::class.java).apply {
            putExtra(ApiInsecureCryptoActivity.EXTRA_DETAIL, detail)
            putExtra(ApiInsecureCryptoActivity.EXTRA_PROBLEM_ID, problemId)
        }
        return PendingIntent.getActivity(
            this,
            problemId.hashCode() xor 0x1ACEC0DE,
            intent,
            apiInteractionPiFlags(),
        )
    }

    /** Reads optional `Charset:` header from ASCII-armored OpenPGP input. */
    private fun armorCharsetOrNull(input: ByteArray): String? {
        if (input.isEmpty()) return null
        val n = minOf(input.size, 512)
        val head = String(input, 0, n, Charsets.UTF_8)
        if (!head.contains("BEGIN PGP", ignoreCase = true)) return null
        val line = head.lineSequence().firstOrNull { it.startsWith("Charset:", ignoreCase = true) }
            ?: return null
        return line.substringAfter(':').trim().takeIf { it.isNotEmpty() }
    }

    /**
     * OpenKeychain-compatible progress: Message.arg1=current, arg2=total.
     * No-ops when [OpenPgpConstants.EXTRA_PROGRESS_MESSENGER] is absent.
     */
    private fun progressReporter(data: Intent): (Int, Int) -> Unit {
        @Suppress("DEPRECATION")
        val messenger = data.getParcelableExtra<Messenger>(OpenPgpConstants.EXTRA_PROGRESS_MESSENGER)
            ?: return { _, _ -> }
        val dataLength = data.getLongExtra(OpenPgpConstants.EXTRA_DATA_LENGTH, -1L)
        var dead = false
        return { current, total ->
            if (!dead) {
                val msg = Message.obtain()
                if (dataLength > 0L && total > 0) {
                    msg.arg1 = ((current.toLong() * dataLength) / total).toInt().coerceAtLeast(0)
                    msg.arg2 = dataLength.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                } else {
                    msg.arg1 = current
                    msg.arg2 = total
                }
                try {
                    messenger.send(msg)
                } catch (_: RemoteException) {
                    dead = true
                }
            }
        }
    }

    private suspend fun handleSign(
        input: ByteArray,
        data: Intent,
        callerPkg: String,
        detached: Boolean,
    ): Pair<ByteArray?, Intent> {
        val signKeyId = resolveSignKeyId(data)
        if (signKeyId == 0L) {
            return null to signKeyPickerFromRequest(callerPkg, data)
        }
        if (!isKeyAllowed(callerPkg, signKeyId)) {
            return null to keyPermissionInteractionResult(
                callerPkg,
                longArrayOf(findSignerSummary(signKeyId)?.masterKeyId ?: signKeyId),
            )
        }
        unlockInteractionOrNull(callerPkg)?.let { return null to it }
        try {
            if (data.getCharArrayExtra(OpenPgpConstants.EXTRA_PASSPHRASE) == null) {
                return null to passphraseInteractionResult(callerPkg)
            }
            val signed = signPayload(input, data, callerPkg, signKeyId, detached)
                ?: return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_signing_failed))
            val micalg = PgpAlgorithmPolicy.openPgpMicalg(signed.hashAlgorithm)
            return if (detached) {
                null to successResult().apply {
                    putExtra(OpenPgpConstants.RESULT_DETACHED_SIGNATURE, signed.output)
                    putExtra(OpenPgpConstants.RESULT_SIGNATURE_MICALG, micalg)
                    putExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, signKeyId)
                }
            } else {
                // Cleartext / inline SIGN: mail clients need micalg for multipart/signed.
                signed.output to successResult().apply {
                    putExtra(OpenPgpConstants.RESULT_SIGNATURE_MICALG, micalg)
                    putExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, signKeyId)
                }
            }
        } catch (e: Exception) {
            Timber.e(e, "OpenPGP sign failed")
            return null to errorResult(OpenPgpError.GENERIC_ERROR, CryptoErrors.safeMessage(e, getString(R.string.api_err_signing_failed)))
        }
    }

    private suspend fun signPayload(
        input: ByteArray,
        data: Intent,
        callerPkg: String,
        signKeyId: Long,
        detached: Boolean,
    ): SignResult? {
        if (!isKeyAllowed(callerPkg, signKeyId)) return null
        requireVaultUnlocked() // defended by handleSign unlockInteractionOrNull
        val masterId = findSignerSummary(signKeyId)?.masterKeyId ?: signKeyId
        val secret = keyRepository.getArmoredSecret(masterId) ?: return null
        val passphrase = data.getCharArrayExtra(OpenPgpConstants.EXTRA_PASSPHRASE) ?: return null
        // DETACHED_SIGN: ASCII armor only when requested (openpgp-api default = binary).
        val asciiArmor = if (detached) {
            data.getBooleanExtra(OpenPgpConstants.EXTRA_REQUEST_ASCII_ARMOR, false)
        } else {
            true
        }
        val customHeaders = ArmorHeaders.fromHeaderLines(
            data.getStringArrayListExtra(OpenPgpConstants.EXTRA_CUSTOM_HEADERS),
        )
        return try {
            cryptoOperations.sign(
                input,
                secret,
                passphrase,
                detachedBinary = detached,
                asciiArmor = asciiArmor,
                customArmorHeaders = customHeaders,
            )
        } finally {
            passphrase.fill('\u0000')
        }
    }

    private suspend fun handleGetKeyIds(data: Intent, callerPkg: String): Pair<ByteArray?, Intent> {
        val userIds = data.getStringArrayExtra(OpenPgpConstants.EXTRA_USER_IDS)
            ?: return null to errorResult(OpenPgpError.NO_USER_IDS, getString(R.string.api_err_missing_user_ids))
        val keyIds = LongArray(userIds.size)
        for (index in userIds.indices) {
            val uid = userIds[index]
            val matches = userIdDao.findByUserIdFragment(uid)
                .map { it.masterKeyId }
                .distinct()
            // OpenKeychain: multiple keys for one address → USER_INTERACTION picker.
            if (matches.size > 1) {
                return null to encryptKeyInteractionResult(callerPkg, data)
            }
            keyIds[index] = matches.firstOrNull()
                ?: autocryptManager.lookup(
                    uid.substringAfter('<').substringBefore('>').ifBlank { uid },
                )
                ?: 0L
        }
        if (keyIds.any { it == 0L }) {
            // OpenKeychain: missing recipient → USER_INTERACTION keyserver/import, not hard NO_USER_IDS.
            val missing = userIds[keyIds.indexOfFirst { it == 0L }]
            return null to Intent().apply {
                putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
                putExtra(OpenPgpConstants.RESULT_INTENT, importMissingByQueryPendingIntent(missing))
            }
        }
        val blocked = keyIds.map { findSignerSummary(it)?.masterKeyId ?: it }
            .distinct()
            .filter { !isKeyAllowed(callerPkg, it) }
        if (blocked.isNotEmpty()) {
            return null to keyPermissionInteractionResult(callerPkg, blocked.toLongArray())
        }
        return null to successResult().apply {
            putExtra(OpenPgpConstants.RESULT_KEY_IDS, keyIds)
        }
    }

    private suspend fun handleGetKey(data: Intent, callerPkg: String): Pair<ByteArray?, Intent> {
        val preferredUserId = data.getStringExtra(OpenPgpConstants.EXTRA_USER_ID)
        val requestedId = data.getLongExtra(OpenPgpConstants.EXTRA_KEY_ID, 0L)
            .takeIf { it != 0L }
            ?: data.getLongExtra(OpenPgpConstants.EXTRA_SIGN_KEY_ID, 0L).takeIf { it != 0L }
            ?: findKeyIdForUserId(preferredUserId)
            ?: 0L
        if (requestedId == 0L) {
            // OKC: missing key_id/user_id match → keyserver import by email when possible.
            preferredUserId?.let { email ->
                return null to Intent().apply {
                    putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
                    putExtra(OpenPgpConstants.RESULT_INTENT, importMissingByQueryPendingIntent(email))
                }
            }
            return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_missing_key_id))
        }
        // Resolve signing-subkey ids to the stored master ring (OpenKeychain GET_KEY).
        val masterId = findSignerSummary(requestedId)?.masterKeyId ?: requestedId
        var armored = keyRepository.getArmoredPublic(masterId)
        if (armored == null) {
            // OKC contract: missing key → USER_INTERACTION import-from-keyserver PendingIntent.
            return null to Intent().apply {
                putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
                putExtra(OpenPgpConstants.RESULT_INTENT, importMissingSignerPendingIntent(requestedId))
            }
        }
        if (!isKeyAllowed(callerPkg, masterId)) {
            return null to keyPermissionInteractionResult(callerPkg, longArrayOf(masterId))
        }
        if (data.getBooleanExtra(OpenPgpConstants.EXTRA_MINIMIZE, false)) {
            val keep = data.getStringExtra(OpenPgpConstants.EXTRA_MINIMIZE_USER_ID) ?: preferredUserId
            armored = KeyRingMinimizer.minimizePublicArmored(armored, keep)
        }
        return armored to successResult().apply {
            putExtra(OpenPgpConstants.EXTRA_KEY_ID, masterId)
        }
    }

    /** Any local key (secret or public) whose UID matches [userId]. */
    private suspend fun findKeyIdForUserId(userId: String?): Long? {
        val wanted = normalizeEmail(userId) ?: return null
        userIdDao.findByUserIdFragment(wanted).firstOrNull()?.masterKeyId?.let { return it }
        autocryptManager.lookup(wanted)?.let { return it }
        for (summary in keyRepository.search("")) {
            val uids = userIdDao.forKey(summary.masterKeyId).map { it.userId }.ifEmpty {
                listOfNotNull(summary.primaryUserId)
            }
            if (uids.any { normalizeEmail(it) == wanted }) return summary.masterKeyId
        }
        return null
    }

    private suspend fun handleGetSignKeyId(data: Intent, callerPkg: String): Pair<ByteArray?, Intent> {
        val explicit = data.getLongExtra(OpenPgpConstants.EXTRA_SIGN_KEY_ID, 0L)
        if (explicit != 0L) {
            if (!isKeyAllowed(callerPkg, explicit)) {
                return null to keyPermissionInteractionResult(
                    callerPkg,
                    longArrayOf(findSignerSummary(explicit)?.masterKeyId ?: explicit),
                )
            }
            return null to successResult().apply {
                putExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, explicit)
                putExtra(OpenPgpConstants.EXTRA_SIGN_KEY_ID, explicit)
                putSignKeyIdentityExtras(this, explicit)
            }
        }
        // K-9 / FairEmail: EXTRA_USER_ID is the account address — prefer a matching secret key.
        val preferredUserId = data.getStringExtra(OpenPgpConstants.EXTRA_USER_ID)
        findSecretKeyForUserId(preferredUserId)?.let { keyId ->
            if (!isKeyAllowed(callerPkg, keyId)) {
                return null to keyPermissionInteractionResult(callerPkg, longArrayOf(keyId))
            }
            return null to successResult().apply {
                putExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, keyId)
                putExtra(OpenPgpConstants.EXTRA_SIGN_KEY_ID, keyId)
                putSignKeyIdentityExtras(this, keyId)
            }
        }
        // Soft preselect from the client (account previously chose this key).
        val preselect = data.getLongExtra(OpenPgpConstants.EXTRA_PRESELECT_KEY_ID, 0L)
        if (preselect != 0L) {
            val master = findSignerSummary(preselect)?.masterKeyId ?: preselect
            val secrets = keyRepository.observeKeys().first()
            if (secrets.any { it.isSecret && it.masterKeyId == master } && isKeyAllowed(callerPkg, master)) {
                return null to successResult().apply {
                    putExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, master)
                    putExtra(OpenPgpConstants.EXTRA_SIGN_KEY_ID, master)
                    putSignKeyIdentityExtras(this, master)
                }
            }
        }
        val settings = settingsRepository.current()
        settings.defaultSignKeyId?.let { keyId ->
            if (!isKeyAllowed(callerPkg, keyId)) {
                return null to keyPermissionInteractionResult(callerPkg, longArrayOf(keyId))
            }
            return null to successResult().apply {
                putExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, keyId)
                putExtra(OpenPgpConstants.EXTRA_SIGN_KEY_ID, keyId)
                putSignKeyIdentityExtras(this, keyId)
            }
        }
        val secrets = keyRepository.observeKeys().first().filter { it.isSecret }
        if (secrets.isEmpty()) {
            return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_no_signing_key))
        }
        // OpenKeychain: no preferred sign key yet → USER_INTERACTION key picker.
        return null to signKeyInteractionResult(
            callerPkg,
            preferredUserId,
            preselect.takeIf { it != 0L },
            data.getBooleanExtra(OpenPgpConstants.EXTRA_SHOW_AUTOCRYPT_HINT, false),
        )
    }

    /** Resolves a secret master key whose UID email matches [userId] (or null). */
    private suspend fun findSecretKeyForUserId(userId: String?): Long? {
        val wanted = normalizeEmail(userId) ?: return null
        for (summary in keyRepository.observeKeys().first().filter { it.isSecret }) {
            val uids = userIdDao.forKey(summary.masterKeyId).map { it.userId }.ifEmpty {
                listOfNotNull(summary.primaryUserId)
            }
            if (uids.any { normalizeEmail(it) == wanted }) return summary.masterKeyId
        }
        return null
    }

    /** K-9 / FairEmail account UI: primary UID + creation time for the signing key. */
    private suspend fun putSignKeyIdentityExtras(result: Intent, keyId: Long) {
        val summary = keyRepository.getKeyDetail(keyId)?.summary
            ?: keyRepository.search("").firstOrNull { it.masterKeyId == keyId }
            ?: return
        summary.primaryUserId?.let {
            result.putExtra(OpenPgpConstants.RESULT_PRIMARY_USER_ID, it)
        }
        if (summary.createdAt > 0L) {
            result.putExtra(OpenPgpConstants.RESULT_KEY_CREATION_TIME, summary.createdAt)
        }
    }

    private suspend fun handleDecryptMetadata(
        input: ByteArray,
        data: Intent,
        callerPkg: String,
    ): Pair<ByteArray?, Intent> {
        // Same decrypt path as DECRYPT_VERIFY, but do not write plaintext to the output pipe.
        val (plaintext, result) = handleDecryptVerify(input, data, callerPkg)
        if (result.getIntExtra(OpenPgpConstants.RESULT_CODE, -1) != OpenPgpConstants.RESULT_CODE_SUCCESS) {
            return null to result
        }
        val fileName = result.getStringExtra(OpenPgpConstants.EXTRA_ORIGINAL_FILENAME) ?: "_CONSOLE"
        val meta = successResult().apply {
            putExtra(OpenPgpConstants.EXTRA_ORIGINAL_FILENAME, fileName)
            result.getLongExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, 0L).takeIf { it != 0L }?.let {
                putExtra(OpenPgpConstants.RESULT_SIGN_KEY_ID, it)
            }
            if (result.hasExtra(OpenPgpConstants.RESULT_SIGNATURE_VERIFIED)) {
                putExtra(
                    OpenPgpConstants.RESULT_SIGNATURE_VERIFIED,
                    result.getBooleanExtra(OpenPgpConstants.RESULT_SIGNATURE_VERIFIED, false),
                )
            }
            @Suppress("DEPRECATION")
            val signature = result.getParcelableExtra<OpenPgpSignatureResult>(OpenPgpConstants.RESULT_SIGNATURE)
                ?: OpenPgpSignatureResult.createWithNoSignature()
            @Suppress("DEPRECATION")
            val decryption = result.getParcelableExtra<OpenPgpDecryptionResult>(OpenPgpConstants.RESULT_DECRYPTION)
                ?: OpenPgpDecryptionResult(OpenPgpDecryptionResult.RESULT_ENCRYPTED)
            @Suppress("DEPRECATION")
            val metadata = result.getParcelableExtra<OpenPgpMetadata>(OpenPgpConstants.RESULT_METADATA)
                ?: OpenPgpMetadata(
                    filename = fileName,
                    mimeType = null,
                    modificationTime = 0L,
                    originalSize = (plaintext?.size ?: 0).toLong(),
                )
            putDecryptVerifyParcelables(this, signature, decryption, metadata)
        }
        return null to meta
    }

    private suspend fun handleBackup(data: Intent, callerPkg: String): Pair<ByteArray?, Intent> {
        val keyIds = data.getLongArrayExtra(OpenPgpConstants.EXTRA_KEY_IDS)
            ?: return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_missing_key_ids))
        val backupSecret = data.getBooleanExtra(OpenPgpConstants.EXTRA_BACKUP_SECRET, false)
        // Secret backup needs an unlocked vault (OpenKeychain always prompts for BACKUP).
        if (backupSecret) {
            unlockInteractionOrNull(callerPkg)?.let { return null to it }
        }
        val masterIds = keyIds.map { findSignerSummary(it)?.masterKeyId ?: it }.distinct()
        val blocked = masterIds.filter { !isKeyAllowed(callerPkg, it) }
        if (blocked.isNotEmpty()) {
            return null to keyPermissionInteractionResult(callerPkg, blocked.toLongArray())
        }
        val builder = StringBuilder()
        val chunks = kotlinx.coroutines.coroutineScope {
            masterIds.map { masterId ->
                async(Dispatchers.IO) {
                    if (backupSecret) {
                        keyRepository.getArmoredSecret(masterId)
                            ?: keyRepository.getArmoredPublic(masterId)
                    } else {
                        // Public-only path — never fall back to exportKeyRing (secret blob).
                        keyRepository.getArmoredPublic(masterId)
                    }
                }
            }.mapNotNull { it.await() }
        }
        for (armored in chunks) {
            builder.append(String(armored, Charsets.UTF_8))
            if (!builder.endsWith("\n")) builder.append('\n')
        }
        if (builder.isEmpty()) {
            return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_no_keys_export))
        }
        return builder.toString().toByteArray(Charsets.UTF_8) to successResult()
    }

    /**
     * OpenKeychain Autocrypt Setup Message: passphrase-encrypt secret key(s) with a
     * Numeric9x4 transfer code, write the armored ciphertext, and return RESULT_INTENT
     * that displays the code to the user.
     */
    private suspend fun handleAutocryptKeyTransfer(
        data: Intent,
        callerPkg: String,
    ): Pair<ByteArray?, Intent> {
        val keyIds = data.getLongArrayExtra(OpenPgpConstants.EXTRA_KEY_IDS)
            ?: return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_missing_key_ids))
        if (keyIds.isEmpty()) {
            return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_missing_key_ids))
        }
        unlockInteractionOrNull(callerPkg)?.let { return null to it }

        val secrets = ArrayList<ByteArray>()
        for (keyId in keyIds) {
            val masterId = findSignerSummary(keyId)?.masterKeyId ?: keyId
            if (!isKeyAllowed(callerPkg, masterId)) {
                return null to keyPermissionInteractionResult(callerPkg, longArrayOf(masterId))
            }
            val secret = keyRepository.getArmoredSecret(masterId)
                ?: return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_no_secret_keys))
            secrets.add(secret)
        }

        val digits = CharArray(36)
        val rng = SecureRandom()
        for (i in digits.indices) {
            digits[i] = ('0'.code + rng.nextInt(10)).toChar()
        }
        val displayCode = buildString {
            for (i in digits.indices) {
                if (i > 0 && i % 4 == 0) append('-')
                append(digits[i])
            }
        }

        val custom = LinkedHashMap<String, String>()
        custom["Autocrypt-Prefer-Encrypt"] = "mutual"
        ArmorHeaders.fromHeaderLines(
            data.getStringArrayListExtra(OpenPgpConstants.EXTRA_CUSTOM_HEADERS),
        ).forEach { (k, v) -> custom[k] = v }

        val plaintext = buildString {
            for (secret in secrets) {
                append(String(secret, Charsets.UTF_8))
                if (!endsWith("\n")) append('\n')
            }
        }.toByteArray(Charsets.UTF_8)

        return try {
            val ciphertext = withContext(Dispatchers.IO) {
                cryptoOperations.encrypt(
                    plaintext = plaintext,
                    recipientPublicArmored = emptyList(),
                    asciiArmor = true,
                    fileName = "_CONSOLE",
                    integrity = MessageIntegrity.MDC,
                    compression = MessageCompression.ZLIB,
                    passphrase = digits,
                    customArmorHeaders = custom,
                ).ciphertext
            }
            val result = successResult()
            result.putExtra(
                OpenPgpConstants.RESULT_INTENT,
                autocryptSetupCodePendingIntent(displayCode),
            )
            ciphertext to result
        } catch (e: Exception) {
            Timber.e(e, "Autocrypt key transfer failed")
            null to errorResult(
                OpenPgpError.GENERIC_ERROR,
                CryptoErrors.safeMessage(e, getString(R.string.api_err_encryption_failed)),
            )
        } finally {
            Arrays.fill(digits, '\u0000')
        }
    }

    private fun autocryptSetupCodePendingIntent(displayCode: String): PendingIntent {
        val intent = Intent(this, ApiAutocryptSetupCodeActivity::class.java).apply {
            putExtra(ApiAutocryptSetupCodeActivity.EXTRA_SETUP_CODE, displayCode)
        }
        return PendingIntent.getActivity(
            this,
            displayCode.hashCode() xor 0xA070C0DE.toInt(),
            intent,
            apiInteractionPiFlags(),
        )
    }

    /**
     * Resolves encrypt recipients. Prefer [EXTRA_KEY_IDS_SELECTED] (post-picker).
     * Opportunistic mode soft-fails with [RecipientResolution.OpportunisticMissing]
     * when nothing usable; non-opportunistic unresolved → [NeedPicker].
     */
    private suspend fun resolveRecipientKeys(data: Intent, callerPkg: String): RecipientResolution {
        val opportunistic = data.getBooleanExtra(OpenPgpConstants.EXTRA_OPPORTUNISTIC_ENCRYPTION, false)
        val selected = data.getLongArrayExtra(OpenPgpConstants.EXTRA_KEY_IDS_SELECTED)
        val byId = selected ?: data.getLongArrayExtra(OpenPgpConstants.EXTRA_KEY_IDS)
        if (byId != null) {
            if (byId.isEmpty()) {
                return if (opportunistic) RecipientResolution.OpportunisticMissing
                else if (selected != null) RecipientResolution.Failed
                else RecipientResolution.NeedPicker
            }
            val slots = kotlinx.coroutines.coroutineScope {
                byId.toList().map { id ->
                    async(Dispatchers.IO) {
                        // K-9 / FairEmail may pass encryption subkey ids — load master ring.
                        val masterId = findSignerSummary(id)?.masterKeyId ?: id
                        if (!isKeyAllowed(callerPkg, masterId)) {
                            return@async EncryptUidSlot.Disallowed(masterId)
                        }
                        if (!keyRepository.isEncryptRecipientAllowed(masterId)) {
                            return@async EncryptUidSlot.Skipped
                        }
                        val pub = keyRepository.getArmoredPublic(masterId)
                            ?: return@async EncryptUidSlot.Skipped
                        EncryptUidSlot.Key(pub)
                    }
                }.map { it.await() }
            }
            val disallowed = slots.filterIsInstance<EncryptUidSlot.Disallowed>()
                .map { it.keyId }
                .distinct()
            if (disallowed.isNotEmpty() && !opportunistic) {
                return RecipientResolution.KeyPermissionNeeded(disallowed.toLongArray())
            }
            val ok = slots.mapNotNull { (it as? EncryptUidSlot.Key)?.bytes }
            if (ok.isNotEmpty()) {
                if (!opportunistic && ok.size != byId.size && selected == null) {
                    return RecipientResolution.NeedPicker
                }
                return RecipientResolution.Ok(ok)
            }
            return when {
                opportunistic -> RecipientResolution.OpportunisticMissing
                selected != null -> RecipientResolution.Failed
                else -> RecipientResolution.NeedPicker
            }
        }
        val userIds = data.getStringArrayExtra(OpenPgpConstants.EXTRA_USER_IDS)
        if (userIds == null || userIds.isEmpty()) {
            return if (opportunistic) RecipientResolution.OpportunisticMissing
            else RecipientResolution.NeedPicker
        }
        val slots = kotlinx.coroutines.coroutineScope {
            userIds.map { uid ->
                async(Dispatchers.IO) {
                    val matches = userIdDao.findByUserIdFragment(uid)
                        .map { it.masterKeyId }
                        .distinct()
                    if (matches.size > 1) return@async EncryptUidSlot.Ambiguous
                    val keyId = matches.firstOrNull()
                        ?: autocryptManager.lookup(
                            uid.substringAfter('<').substringBefore('>').ifBlank { uid },
                        )
                    if (keyId == null) return@async EncryptUidSlot.Missing(uid)
                    if (!isKeyAllowed(callerPkg, keyId)) return@async EncryptUidSlot.Disallowed(keyId)
                    if (!keyRepository.isEncryptRecipientAllowed(keyId)) return@async EncryptUidSlot.Skipped
                    val pub = keyRepository.getArmoredPublic(keyId) ?: return@async EncryptUidSlot.Skipped
                    EncryptUidSlot.Key(pub)
                }
            }.map { it.await() }
        }
        if (slots.any { it is EncryptUidSlot.Ambiguous }) {
            return if (opportunistic) RecipientResolution.OpportunisticMissing
            else RecipientResolution.NeedPicker
        }
        val firstMissing = slots.filterIsInstance<EncryptUidSlot.Missing>().firstOrNull()
        if (firstMissing != null && !opportunistic) {
            return RecipientResolution.MissingRecipient(firstMissing.userId)
        }
        val disallowed = slots.filterIsInstance<EncryptUidSlot.Disallowed>()
            .map { findSignerSummary(it.keyId)?.masterKeyId ?: it.keyId }
            .distinct()
        if (disallowed.isNotEmpty() && !opportunistic) {
            return RecipientResolution.KeyPermissionNeeded(disallowed.toLongArray())
        }
        val ok = slots.mapNotNull { (it as? EncryptUidSlot.Key)?.bytes }
        if (ok.isNotEmpty() && (opportunistic || ok.size == userIds.size)) {
            return RecipientResolution.Ok(ok)
        }
        if (ok.isEmpty() && opportunistic) return RecipientResolution.OpportunisticMissing
        if (!opportunistic) return RecipientResolution.NeedPicker
        return if (ok.isEmpty()) RecipientResolution.OpportunisticMissing else RecipientResolution.Ok(ok)
    }

    /** Per-UID outcome from [resolveRecipientKeys] EXTRA_USER_IDS branch. */
    private sealed class EncryptUidSlot {
        data class Key(val bytes: ByteArray) : EncryptUidSlot()
        data class Missing(val userId: String) : EncryptUidSlot()
        data class Disallowed(val keyId: Long) : EncryptUidSlot()
        data object Ambiguous : EncryptUidSlot()
        data object Skipped : EncryptUidSlot()
    }

    private sealed class RecipientResolution {
        data class Ok(val keys: List<ByteArray>) : RecipientResolution()
        data object NeedPicker : RecipientResolution()
        /** Address not on the keyring — import/keyserver PendingIntent (like GET_KEY_IDS). */
        data class MissingRecipient(val userId: String) : RecipientResolution()
        /** Local key blocked by per-app allowlist — grant PendingIntent. */
        data class KeyPermissionNeeded(val masterKeyIds: LongArray) : RecipientResolution()
        data object OpportunisticMissing : RecipientResolution()
        data object Failed : RecipientResolution()
    }

    private suspend fun handleQueryAutocryptStatus(data: Intent): Pair<ByteArray?, Intent> {
        val peers = buildList {
            data.getStringArrayExtra(OpenPgpConstants.EXTRA_USER_IDS)?.forEach { add(it) }
            data.getStringExtra(OpenPgpConstants.EXTRA_SENDER_ADDRESS)?.let { add(it) }
        }.mapNotNull { normalizeEmail(it) }.distinct()
        if (peers.isEmpty()) {
            return null to errorResult(OpenPgpError.NO_USER_IDS, getString(R.string.api_err_missing_user_ids))
        }
        var worst = OpenPgpConstants.AUTOCRYPT_STATUS_MUTUAL
        var allConfirmed = true
        for (email in peers) {
            val (status, confirmed) = autocryptStatusForEmail(email)
            worst = minOf(worst, status)
            if (!confirmed) allConfirmed = false
        }
        return null to successResult().apply {
            putExtra(OpenPgpConstants.RESULT_AUTOCRYPT_STATUS, worst)
            putExtra(OpenPgpConstants.RESULT_KEYS_CONFIRMED, allConfirmed &&
                worst >= OpenPgpConstants.AUTOCRYPT_STATUS_AVAILABLE)
        }
    }

    private suspend fun handleUpdateAutocryptPeer(data: Intent): Pair<ByteArray?, Intent> {
        val peerId = data.getStringExtra(OpenPgpConstants.EXTRA_AUTOCRYPT_PEER_ID)
            ?: return null to errorResult(OpenPgpError.NO_USER_IDS, getString(R.string.api_err_missing_user_ids))
        @Suppress("DEPRECATION")
        val update = data.getParcelableExtra<AutocryptPeerUpdate>(OpenPgpConstants.EXTRA_AUTOCRYPT_PEER_UPDATE)
        val preferMutual = update?.getPreferEncrypt() == AutocryptPeerUpdate.PreferEncrypt.MUTUAL
        val keyId = autocryptManager.storePeerKeyData(peerId, update?.getKeyData(), preferMutual)
            ?: return null to errorResult(OpenPgpError.GENERIC_ERROR, getString(R.string.api_err_key_not_found))
        ingestGossipUpdates(data)
        return null to successResult().apply {
            putExtra(OpenPgpConstants.RESULT_KEY_IDS, longArrayOf(keyId))
        }
    }

    /**
     * Ingests Autocrypt peer / gossip extras attached to DECRYPT_VERIFY.
     * Returns OK / NEW / MISMATCH for the primary peer when present.
     */
    private suspend fun ingestAutocryptPeerExtras(
        data: Intent,
    ): OpenPgpSignatureResult.AutocryptPeerResult? {
        val peerId = data.getStringExtra(OpenPgpConstants.EXTRA_AUTOCRYPT_PEER_ID)
        @Suppress("DEPRECATION")
        val update = data.getParcelableExtra<AutocryptPeerUpdate>(OpenPgpConstants.EXTRA_AUTOCRYPT_PEER_UPDATE)
        ingestGossipUpdates(data)
        if (peerId.isNullOrBlank() || update == null || !update.hasKeyData()) {
            return null
        }
        val before = autocryptManager.lookup(peerId)
        val preferMutual = update.getPreferEncrypt() == AutocryptPeerUpdate.PreferEncrypt.MUTUAL
        val after = autocryptManager.storePeerKeyData(peerId, update.getKeyData(), preferMutual) ?: return null
        return when {
            before == null -> OpenPgpSignatureResult.AutocryptPeerResult.NEW
            before != after -> OpenPgpSignatureResult.AutocryptPeerResult.MISMATCH
            else -> OpenPgpSignatureResult.AutocryptPeerResult.OK
        }
    }

    private suspend fun ingestGossipUpdates(data: Intent) {
        @Suppress("DEPRECATION")
        val gossip = data.getParcelableArrayListExtra<AutocryptPeerUpdate>(
            OpenPgpConstants.EXTRA_AUTOCRYPT_PEER_GOSSIP_UPDATES,
        ).orEmpty()
        // Gossip peers are identified by EXTRA_USER_IDS parallel list when present; otherwise skip addr.
        val gossipAddrs = data.getStringArrayExtra(OpenPgpConstants.EXTRA_USER_IDS)
        gossip.forEachIndexed { index, peerUpdate ->
            if (!peerUpdate.hasKeyData()) return@forEachIndexed
            val addr = gossipAddrs?.getOrNull(index)
                ?: data.getStringExtra(OpenPgpConstants.EXTRA_AUTOCRYPT_PEER_ID)
                ?: return@forEachIndexed
            val preferMutual = peerUpdate.getPreferEncrypt() == AutocryptPeerUpdate.PreferEncrypt.MUTUAL
            autocryptManager.storePeerKeyData(addr, peerUpdate.getKeyData(), preferMutual)
        }
    }

    private suspend fun autocryptStatusForEmail(email: String): Pair<Int, Boolean> {
        val keyId = userIdDao.findByUserIdFragment(email).firstOrNull()?.masterKeyId
            ?: autocryptManager.lookup(email)
            ?: return OpenPgpConstants.AUTOCRYPT_STATUS_UNAVAILABLE to false
        val summary = keyRepository.getKeyDetail(keyId)?.summary
            ?: return OpenPgpConstants.AUTOCRYPT_STATUS_UNAVAILABLE to false
        if (summary.isRevoked || summary.isExpired || summary.trustLevel == KeySummary.TRUST_NEVER) {
            return OpenPgpConstants.AUTOCRYPT_STATUS_DISCOURAGE to false
        }
        if (!keyRepository.isEncryptRecipientAllowed(keyId)) {
            return OpenPgpConstants.AUTOCRYPT_STATUS_DISCOURAGE to false
        }
        val confirmed = summary.trustLevel == KeySummary.TRUST_FULL
        val status = if (autocryptManager.prefersMutual(email)) {
            OpenPgpConstants.AUTOCRYPT_STATUS_MUTUAL
        } else {
            OpenPgpConstants.AUTOCRYPT_STATUS_AVAILABLE
        }
        return status to confirmed
    }

    private suspend fun resolveSignKeyId(data: Intent): Long {
        val explicit = data.getLongExtra(OpenPgpConstants.EXTRA_SIGN_KEY_ID, 0L)
        if (explicit != 0L) return explicit
        findSecretKeyForUserId(data.getStringExtra(OpenPgpConstants.EXTRA_USER_ID))?.let { return it }
        val settings = settingsRepository.current()
        settings.defaultSignKeyId?.let { return it }
        val secrets = keyRepository.observeKeys().first().filter { it.isSecret }
        // OpenKeychain: ambiguous signing identity → USER_INTERACTION (return 0).
        if (secrets.size != 1) return 0L
        return secrets.first().masterKeyId
    }

    /** Picker Intent extras aligned with [handleGetSignKeyId]. */
    private fun signKeyPickerFromRequest(callerPkg: String, data: Intent): Intent =
        signKeyInteractionResult(
            callerPkg,
            data.getStringExtra(OpenPgpConstants.EXTRA_USER_ID),
            data.getLongExtra(OpenPgpConstants.EXTRA_PRESELECT_KEY_ID, 0L).takeIf { it != 0L },
            data.getBooleanExtra(OpenPgpConstants.EXTRA_SHOW_AUTOCRYPT_HINT, false),
        )

    /**
     * Appends the signing key's public ring when not already among recipients
     * (OpenKeychain `setAdditionalEncryptId` / encrypt-to-self for Sent folder).
     */
    private suspend fun withEncryptToSelf(
        recipients: List<ByteArray>,
        signKeyId: Long,
    ): List<ByteArray> {
        val masterId = findSignerSummary(signKeyId)?.masterKeyId ?: signKeyId
        val already = recipients.any { armored ->
            runCatching {
                KeyRingReader().readPublicKeyRing(armored.inputStream()).masterKeyId == masterId
            }.getOrDefault(false)
        }
        if (already) return recipients
        val selfPub = keyRepository.getArmoredPublic(masterId) ?: return recipients
        return recipients + selfPub
    }

    /** Master + subkey ids for every allowed secret ring (PKESK preflight). */
    private suspend fun collectLocalSecretKeyIds(secretKeys: List<KeySummary>): Set<Long> {
        val ids = HashSet<Long>()
        for (summary in secretKeys) {
            ids.add(summary.masterKeyId)
            keyRepository.getKeyDetail(summary.masterKeyId)?.subkeys?.forEach { ids.add(it.keyId) }
        }
        return ids
    }

    /** Masters that can decrypt [pkeskIds] but are not yet allowed for [callerPkg]. */
    private suspend fun disallowedMastersForPkesk(
        callerPkg: String,
        allSecrets: List<KeySummary>,
        pkeskIds: List<Long>,
    ): LongArray {
        val pkesk = pkeskIds.toHashSet()
        val needed = ArrayList<Long>()
        for (summary in allSecrets) {
            if (isKeyAllowed(callerPkg, summary.masterKeyId)) continue
            val ids = collectLocalSecretKeyIds(listOf(summary))
            if (ids.any { it in pkesk }) needed.add(summary.masterKeyId)
        }
        return needed.toLongArray()
    }

    /**
     * Local signer present but not allowlisted for [callerPkg] → grant PendingIntent
     * (OpenKeychain key permission), not KEY_MISSING / import.
     */
    private suspend fun signerAllowlistInteractionOrNull(
        callerPkg: String,
        signerKeyId: Long?,
    ): Intent? {
        if (signerKeyId == null) return null
        val master = findSignerSummary(signerKeyId)?.masterKeyId ?: return null
        if (isKeyAllowed(callerPkg, master)) return null
        return keyPermissionInteractionResult(callerPkg, longArrayOf(master))
    }

    private fun keyPermissionInteractionResult(packageName: String, masterKeyIds: LongArray): Intent {
        val grant = Intent(this, ApiGrantKeyPermissionActivity::class.java).apply {
            putExtra(ApiGrantKeyPermissionActivity.EXTRA_PACKAGE, packageName)
            putExtra(ApiGrantKeyPermissionActivity.EXTRA_KEY_IDS, masterKeyIds)
        }
        val pending = PendingIntent.getActivity(
            this,
            packageName.hashCode() xor masterKeyIds.contentHashCode() xor 0x4B4559,
            grant,
            apiInteractionPiFlags(),
        )
        return Intent().apply {
            putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpConstants.RESULT_INTENT, pending)
        }
    }

    private suspend fun isKeyAllowed(packageName: String, keyId: Long): Boolean {
        if (keyId == 0L) return false
        val masterId = findSignerSummary(keyId)?.masterKeyId ?: keyId
        val allowed = apiAllowedKeyDao.allowedKeyIds(packageName)
        return allowed.isEmpty() || masterId in allowed || keyId in allowed
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

    /**
     * OpenKeychain / openpgp-api clients start RESULT_INTENT via IntentSender and may
     * supply a fill-in Intent — requires [PendingIntent.FLAG_MUTABLE] on API 31+.
     */
    private fun apiInteractionPiFlags(): Int =
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE

    private fun userInteractionResult(packageName: String): Intent {
        val grant = Intent(this, GrantApiAccessActivity::class.java).apply {
            putExtra(GrantApiAccessActivity.EXTRA_PACKAGE, packageName)
        }
        val pending = PendingIntent.getActivity(
            this,
            packageName.hashCode(),
            grant,
            apiInteractionPiFlags(),
        )
        return Intent().apply {
            putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpConstants.RESULT_INTENT, pending)
        }
    }

    /**
     * OpenKeychain-style passphrase prompt. Distinct from [userInteractionResult]
     * (API grant consent) so clients are not shown the grant dialog again.
     */
    private fun unlockInteractionResult(packageName: String): Intent {
        val unlock = Intent(this, ApiUnlockActivity::class.java).apply {
            putExtra(ApiUnlockActivity.EXTRA_CALLER_PACKAGE, packageName)
        }
        val pending = PendingIntent.getActivity(
            this,
            packageName.hashCode() xor 0x1111_2222,
            unlock,
            apiInteractionPiFlags(),
        )
        return Intent().apply {
            putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpConstants.RESULT_INTENT, pending)
        }
    }

    private fun passphraseInteractionResult(packageName: String): Intent {
        val prompt = Intent(this, ApiPassphraseActivity::class.java).apply {
            putExtra(ApiPassphraseActivity.EXTRA_CALLER_PACKAGE, packageName)
        }
        val pending = PendingIntent.getActivity(
            this,
            packageName.hashCode() xor 0x5A5A_5A5A,
            prompt,
            apiInteractionPiFlags(),
        )
        return Intent().apply {
            putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpConstants.RESULT_INTENT, pending)
        }
    }

    private fun signKeyInteractionResult(
        packageName: String,
        preferredUserId: String? = null,
        preselectKeyId: Long? = null,
        showAutocryptHint: Boolean = false,
    ): Intent {
        val picker = Intent(this, ApiSelectSignKeyActivity::class.java).apply {
            putExtra(ApiSelectSignKeyActivity.EXTRA_CALLER_PACKAGE, packageName)
            preferredUserId?.let { putExtra(OpenPgpConstants.EXTRA_USER_ID, it) }
            preselectKeyId?.let { putExtra(OpenPgpConstants.EXTRA_PRESELECT_KEY_ID, it) }
            if (showAutocryptHint) {
                putExtra(OpenPgpConstants.EXTRA_SHOW_AUTOCRYPT_HINT, true)
            }
        }
        val pending = PendingIntent.getActivity(
            this,
            packageName.hashCode() xor 0xA5A5_A5A5.toInt(),
            picker,
            apiInteractionPiFlags(),
        )
        return Intent().apply {
            putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpConstants.RESULT_INTENT, pending)
        }
    }

    private fun encryptKeyInteractionResult(packageName: String, request: Intent? = null): Intent {
        val picker = Intent(this, ApiSelectEncryptKeyActivity::class.java).apply {
            putExtra(ApiSelectEncryptKeyActivity.EXTRA_CALLER_PACKAGE, packageName)
            request?.getStringArrayExtra(OpenPgpConstants.EXTRA_USER_IDS)?.let { uids ->
                putExtra(OpenPgpConstants.EXTRA_USER_IDS, uids)
            }
        }
        val pending = PendingIntent.getActivity(
            this,
            packageName.hashCode() xor 0x3C3C3C3C,
            picker,
            apiInteractionPiFlags(),
        )
        return Intent().apply {
            putExtra(OpenPgpConstants.RESULT_CODE, OpenPgpConstants.RESULT_CODE_USER_INTERACTION_REQUIRED)
            putExtra(OpenPgpConstants.RESULT_INTENT, pending)
        }
    }
}
