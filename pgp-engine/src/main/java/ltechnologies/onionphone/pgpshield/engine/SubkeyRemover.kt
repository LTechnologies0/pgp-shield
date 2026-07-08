package ltechnologies.onionphone.pgpshield.engine

/**
 * Removes subkeys from an OpenPGP secret key ring.
 *
 * Strips a non-master subkey by key ID and returns the updated armored secret ring.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/**
 * Parameters for removing a subkey from a secret key ring.
 *
 * @property secretKeyRingArmored ASCII-armored secret key ring to modify.
 * @property subkeyId 64-bit key ID of the subkey to remove.
 */
data class RemoveSubkeyRequest(
    val secretKeyRingArmored: ByteArray,
    val subkeyId: Long,
)

/** Removes non-master subkeys from OpenPGP secret key rings. */
class SubkeyRemover {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Removes the subkey identified by [RemoveSubkeyRequest.subkeyId].
     *
     * @return Updated armored secret key ring.
     * @throws IllegalArgumentException if removing the master or the only key.
     * @throws PgpException if the subkey ID is not found.
     */
    fun removeSubkey(request: RemoveSubkeyRequest): ByteArray {
        val ring = PGPUtil.getDecoderStream(ByteArrayInputStream(request.secretKeyRingArmored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }
        val count = ring.secretKeys.asSequence().count()
        require(count > 1) { "Cannot remove the only key in the ring" }
        require(ring.secretKey.keyID != request.subkeyId) { "Cannot remove the master key" }
        val toRemove = ring.secretKeys.asSequence().firstOrNull { it.keyID == request.subkeyId }
            ?: throw PgpException("Subkey ${request.subkeyId} not found")
        val updated = PGPSecretKeyRing.removeSecretKey(ring, toRemove)
        return ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> updated.encode(armor) }
            out.toByteArray()
        }
    }
}
