package ltechnologies.onionphone.pgpshield.engine

/**
 * Passphrase change for OpenPGP secret key rings.
 *
 * Re-encrypts all secret key packets in a ring with a new passphrase while
 * preserving key material and certifications. Each packet's S2K runs in parallel.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlinx.coroutines.runBlocking
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil

/**
 * Parameters for changing the passphrase on a secret key ring.
 *
 * @property secretKeyRingArmored Armored secret key ring to re-encrypt.
 * @property oldPassphrase Current passphrase.
 * @property newPassphrase New passphrase to apply to all secret keys.
 */
data class ChangePassphraseRequest(
    val secretKeyRingArmored: ByteArray,
    val oldPassphrase: CharArray,
    val newPassphrase: CharArray,
    /** When `true`, rewrap with AEAD+Argon2 secret-key protection. */
    val aeadProtect: Boolean = true,
)

/** Re-encrypts secret key rings with a new passphrase. */
class KeyPassphraseChanger {
    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Changes the passphrase on every secret key in the ring.
     *
     * Sync boundary — prefer [changePassphraseSuspending] from coroutines.
     */
    fun changePassphrase(request: ChangePassphraseRequest): ByteArray =
        runBlocking { changePassphraseSuspending(request) }

    /** Parallel S2K rewrap of every secret packet (order preserved). */
    suspend fun changePassphraseSuspending(request: ChangePassphraseRequest): ByteArray {
        CryptoProgress.stage(CryptoStage.PARSE_KEYS)
        val secretRing = PGPUtil.getDecoderStream(ByteArrayInputStream(request.secretKeyRingArmored)).use { input ->
            PGPObjectFactory(input, PgpFingerprints.calculator).nextObject() as PGPSecretKeyRing
        }
        val secretKeys = secretRing.secretKeys.asSequence().toList()
        CryptoProgress.stage(CryptoStage.S2K_PROTECT)
        val newKeys = BcParallel.map(secretKeys) { sk ->
            val useBc = PgpOperators.useBcForPublicKey(sk.publicKey)
            val oldDecryptor = PgpOperators.secretKeyDecryptor(request.oldPassphrase, useBc)
            val newEncryptor = if (request.aeadProtect) {
                PgpOperators.aeadSecretKeyEncryptor(request.newPassphrase, sk.publicKey)
            } else {
                PgpOperators.secretKeyEncryptor(request.newPassphrase, useBc)
            }
            try {
                PGPSecretKey.copyWithNewPassword(sk, oldDecryptor, newEncryptor)
            } catch (e: Exception) {
                if (PgpOperators.isPassphraseChecksumMismatch(e)) throw e
                val altOld = PgpOperators.secretKeyDecryptor(request.oldPassphrase, !useBc)
                val altNew = if (request.aeadProtect) {
                    PgpOperators.aeadSecretKeyEncryptor(request.newPassphrase, sk.publicKey)
                } else {
                    PgpOperators.secretKeyEncryptor(request.newPassphrase, !useBc)
                }
                PGPSecretKey.copyWithNewPassword(sk, altOld, altNew)
            }
        }
        CryptoProgress.stage(CryptoStage.ARMOR)
        val newRing = PGPSecretKeyRing(newKeys)
        return ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> newRing.encode(armor) }
            out.toByteArray()
        }
    }
}
