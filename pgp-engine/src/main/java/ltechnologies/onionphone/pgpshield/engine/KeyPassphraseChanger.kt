package ltechnologies.onionphone.pgpshield.engine

/**
 * Passphrase change for OpenPGP secret key rings.
 *
 * Re-encrypts all secret key packets in a ring with a new passphrase while
 * preserving key material and certifications.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

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
)

/** Re-encrypts secret key rings with a new passphrase. */
class KeyPassphraseChanger {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Changes the passphrase on every secret key in the ring.
     *
     * @return Updated armored secret key ring.
     * @throws Exception if [ChangePassphraseRequest.oldPassphrase] is incorrect.
     */
    fun changePassphrase(request: ChangePassphraseRequest): ByteArray {
        val secretRing = PGPUtil.getDecoderStream(ByteArrayInputStream(request.secretKeyRingArmored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }
        val newKeys = ArrayList<PGPSecretKey>()
        val iter = secretRing.secretKeys
        while (iter.hasNext()) {
            val sk = iter.next()
            val useBc = PgpOperators.useBcForPublicKey(sk.publicKey)
            val oldDecryptor = PgpOperators.secretKeyDecryptor(request.oldPassphrase, useBc)
            val newEncryptor = PgpOperators.secretKeyEncryptor(request.newPassphrase, useBc)
            newKeys.add(
                try {
                    PGPSecretKey.copyWithNewPassword(sk, oldDecryptor, newEncryptor)
                } catch (_: Exception) {
                    val jceOld = PgpOperators.secretKeyDecryptor(request.oldPassphrase, false)
                    val bcNew = PgpOperators.secretKeyEncryptor(request.newPassphrase, true)
                    PGPSecretKey.copyWithNewPassword(sk, jceOld, bcNew)
                },
            )
        }
        val newRing = PGPSecretKeyRing(newKeys)
        return ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> newRing.encode(armor) }
            out.toByteArray()
        }
    }
}
