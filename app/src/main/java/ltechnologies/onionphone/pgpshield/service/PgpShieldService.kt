package ltechnologies.onionphone.pgpshield.service

/**
 * Bound service exposing PGP Shield's native AIDL API (`IPgpShieldService`).
 *
 * Unlike [OpenPgpApiService], this is the app's first-party binder contract used
 * by tightly integrated clients for permission checks, encrypt/decrypt/sign and
 * key listing.
 */

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import dagger.hilt.android.AndroidEntryPoint
import ltechnologies.onionphone.pgpshield.api.CallerIdentity
import ltechnologies.onionphone.pgpshield.api.CryptoResultParcel
import ltechnologies.onionphone.pgpshield.api.DecryptRequestParcel
import ltechnologies.onionphone.pgpshield.api.EncryptRequestParcel
import ltechnologies.onionphone.pgpshield.api.IPgpShieldService
import ltechnologies.onionphone.pgpshield.api.KeySummaryParcel
import ltechnologies.onionphone.pgpshield.api.SignRequestParcel
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.db.ApiAllowedKeyDao
import ltechnologies.onionphone.pgpshield.data.db.ApiAppDao
import ltechnologies.onionphone.pgpshield.util.CallerVerifier
import ltechnologies.onionphone.pgpshield.util.CryptoErrors
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import timber.log.Timber

// ponytail: native PgpShieldClient AIDL also available (:api-client); OpenPGP v11 via OpenPgpApiService.
/**
 * Hilt-injected [Service] implementing the first-party [IPgpShieldService] AIDL.
 *
 * Every binder call verifies the caller's package via [CallerVerifier], checks
 * that the app is granted and that the requested key is permitted, then runs
 * crypto on a background dispatcher (never the binder thread). Passphrases are
 * copied defensively and wiped in `finally` blocks.
 */
@AndroidEntryPoint
class PgpShieldService : Service() {
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var apiAppDao: ApiAppDao
    @Inject lateinit var apiAllowedKeyDao: ApiAllowedKeyDao
    @Inject lateinit var cryptoOperations: CryptoOperations

    // ponytail: binder thread must not run crypto; Default pool only
    private val cryptoDispatcher = Dispatchers.Default

    private val binder = object : IPgpShieldService.Stub() {
        override fun checkPermission(caller: CallerIdentity): Int = runBlocking(cryptoDispatcher) {
            try {
                val pkg = CallerVerifier.verifiedPackage(this@PgpShieldService, caller)
                if (apiAppDao.get(pkg) != null) 0 else 1
            } catch (e: Exception) {
                Timber.e(e, "checkPermission failed")
                2
            }
        }

        override fun encrypt(request: EncryptRequestParcel): CryptoResultParcel = runBlocking(cryptoDispatcher) {
            try {
                val pkg = CallerVerifier.verifiedPackage(this@PgpShieldService, request.caller)
                ensureGranted(pkg)
                val publicKeys = request.recipientKeyIds.toList().mapNotNull { id ->
                    ensureKeyAllowed(pkg, id)
                    keyRepository.getArmoredPublic(id)
                }
                if (publicKeys.isEmpty()) {
                    return@runBlocking CryptoResultParcel(false, errorMessage = "No recipient keys")
                }
                val result = cryptoOperations.encrypt(request.plaintext, publicKeys, request.asciiArmor)
                CryptoResultParcel(true, output = result.ciphertext)
            } catch (e: SecurityException) {
                CryptoResultParcel(false, errorMessage = "Permission denied")
            } catch (e: Exception) {
                Timber.e(e, "encrypt failed")
                CryptoResultParcel(false, errorMessage = CryptoErrors.safeMessage(e, "Encryption failed"))
            }
        }

        override fun decrypt(request: DecryptRequestParcel): CryptoResultParcel = runBlocking(cryptoDispatcher) {
            var passphrase: CharArray? = null
            try {
                val pkg = CallerVerifier.verifiedPackage(this@PgpShieldService, request.caller)
                ensureGranted(pkg)
                ensureKeyAllowed(pkg, request.decryptKeyId)
                val secret = keyRepository.getArmoredSecret(request.decryptKeyId)
                    ?: return@runBlocking CryptoResultParcel(
                        false,
                        errorMessage = "Secret key not found",
                        requiresUserInteraction = true,
                    )
                passphrase = request.passphrase?.copyOf()
                    ?: return@runBlocking CryptoResultParcel(
                        false,
                        errorMessage = "Passphrase required",
                        requiresUserInteraction = true,
                    )
                val result = cryptoOperations.decrypt(request.ciphertext, secret, passphrase)
                CryptoResultParcel(true, output = result.plaintext)
            } catch (e: SecurityException) {
                CryptoResultParcel(false, errorMessage = "Permission denied")
            } catch (e: Exception) {
                Timber.e(e, "decrypt failed")
                CryptoResultParcel(false, errorMessage = CryptoErrors.safeMessage(e, "Decryption failed"))
            } finally {
                passphrase?.fill('\u0000')
            }
        }

        override fun sign(request: SignRequestParcel): CryptoResultParcel = runBlocking(cryptoDispatcher) {
            var passphrase: CharArray? = null
            try {
                val pkg = CallerVerifier.verifiedPackage(this@PgpShieldService, request.caller)
                ensureGranted(pkg)
                ensureKeyAllowed(pkg, request.signKeyId)
                val secret = keyRepository.getArmoredSecret(request.signKeyId)
                    ?: return@runBlocking CryptoResultParcel(false, errorMessage = "Secret key not found")
                passphrase = request.passphrase?.copyOf()
                    ?: return@runBlocking CryptoResultParcel(
                        false,
                        errorMessage = "Passphrase required",
                        requiresUserInteraction = true,
                    )
                val result = cryptoOperations.sign(request.data, secret, passphrase)
                CryptoResultParcel(true, output = result.output)
            } catch (e: SecurityException) {
                CryptoResultParcel(false, errorMessage = "Permission denied")
            } catch (e: Exception) {
                Timber.e(e, "sign failed")
                CryptoResultParcel(false, errorMessage = CryptoErrors.safeMessage(e, "Signing failed"))
            } finally {
                passphrase?.fill('\u0000')
            }
        }

        override fun listKeys(packageName: String): MutableList<KeySummaryParcel> = runBlocking(cryptoDispatcher) {
            try {
                val caller = CallerIdentity(packageName, Binder.getCallingUid())
                val pkg = CallerVerifier.verifiedPackage(this@PgpShieldService, caller)
                if (apiAppDao.get(pkg) == null) return@runBlocking mutableListOf()
                val allowed = apiAllowedKeyDao.allowedKeyIds(pkg)
                keyRepository.search("").mapNotNull { key ->
                    if (allowed.isNotEmpty() && key.masterKeyId !in allowed) return@mapNotNull null
                    KeySummaryParcel(key.masterKeyId, key.fingerprint, key.primaryUserId, key.isSecret)
                }.toMutableList()
            } catch (e: Exception) {
                Timber.e(e, "listKeys failed")
                mutableListOf()
            }
        }
    }

    private suspend fun ensureGranted(packageName: String) {
        if (apiAppDao.get(packageName) == null) throw SecurityException("API not granted")
    }

    private suspend fun ensureKeyAllowed(packageName: String, keyId: Long) {
        val allowed = apiAllowedKeyDao.allowedKeyIds(packageName)
        if (allowed.isNotEmpty() && keyId !in allowed) {
            throw SecurityException("Key not allowed for app")
        }
    }

    /** Returns the PGP Shield AIDL binder to connecting clients. */
    override fun onBind(intent: Intent?): IBinder = binder

    /** Keeps the service sticky so the system restarts it after being killed. */
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY
}
