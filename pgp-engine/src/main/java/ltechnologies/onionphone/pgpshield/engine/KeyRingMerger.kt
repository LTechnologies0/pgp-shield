package ltechnologies.onionphone.pgpshield.engine

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPUtil

/** Merges two public key rings of the same master key via [PGPPublicKeyRing.join]. */
object KeyRingMerger {
    /**
     * Joins [existingArmored] with [incomingArmored] when they share a master key.
     * Returns [incomingArmored] unchanged when the rings do not match.
     */
    fun joinPublic(existingArmored: ByteArray, incomingArmored: ByteArray): ByteArray {
        val existing = readPublic(existingArmored) ?: return incomingArmored
        val incoming = readPublic(incomingArmored) ?: return incomingArmored
        if (existing.publicKey.keyID != incoming.publicKey.keyID) return incomingArmored
        val joined = PGPPublicKeyRing.join(existing, incoming)
        return armor(joined.encoded)
    }

    private fun readPublic(armored: ByteArray): PGPPublicKeyRing? =
        try {
            PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
                PGPObjectFactory(input, PgpFingerprints.calculator).nextObject() as? PGPPublicKeyRing
            }
        } catch (_: Exception) {
            null
        }

    private fun armor(data: ByteArray): ByteArray =
        ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> armor.write(data) }
            out.toByteArray()
        }
}
