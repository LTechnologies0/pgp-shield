package ltechnologies.onionphone.pgpshield.engine

/**
 * Exports public key material from secret key rings.
 *
 * Strips secret packets and returns ASCII-armored public key rings suitable for sharing.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/** Converts armored secret key rings to armored public key rings. */
object KeyRingExporter {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Extracts the public key ring from an armored secret key ring.
     *
     * @param secretArmored ASCII-armored secret key ring bytes.
     * @return ASCII-armored public key ring with the same keys (no secret material).
     */
    fun publicArmoredFromSecret(secretArmored: ByteArray): ByteArray {
        val secretRing = PGPUtil.getDecoderStream(ByteArrayInputStream(secretArmored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }
        val publicKeys = ArrayList<PGPPublicKey>()
        val iter = secretRing.secretKeys
        while (iter.hasNext()) {
            publicKeys.add(iter.next().publicKey)
        }
        return armor(PGPPublicKeyRing(publicKeys).encoded)
    }

    private fun armor(data: ByteArray): ByteArray =
        ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> armor.write(data) }
            out.toByteArray()
        }
}
