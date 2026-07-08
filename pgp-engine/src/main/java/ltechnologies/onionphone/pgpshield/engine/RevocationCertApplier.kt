package ltechnologies.onionphone.pgpshield.engine

/**
 * Applies standalone key revocation certificates to key rings.
 *
 * Merges an armored key-revocation signature onto a public or secret key ring,
 * marking the master key as revoked per OpenPGP rules.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/** Merges armored revocation signatures into public or secret key rings. */
class RevocationCertApplier {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Applies [revocationArmored] to a public key ring.
     *
     * @return Updated armored public key ring with revocation on the master key.
     */
    fun applyToPublicKeyRing(publicArmored: ByteArray, revocationArmored: ByteArray): ByteArray {
        val ring = loadPublicRing(publicArmored)
        val revocation = loadRevocation(revocationArmored)
        val revokedMaster = PGPPublicKey.addCertification(ring.publicKey, revocation)
        val updated = replaceMasterKeyInRing(ring, revokedMaster)
        return armorPublicRing(updated)
    }

    /**
     * Applies [revocationArmored] to a secret key ring (updates embedded public packets).
     *
     * @return Updated armored secret key ring.
     */
    fun applyToSecretKeyRing(secretArmored: ByteArray, revocationArmored: ByteArray): ByteArray {
        val ring = loadSecretRing(secretArmored)
        val revocation = loadRevocation(revocationArmored)
        val masterSecret = ring.secretKey
        val revokedPublic = PGPPublicKey.addCertification(masterSecret.publicKey, revocation)
        val updated = PGPSecretKeyRing.insertOrReplacePublicKey(ring, revokedPublic)
        return armorSecretRing(updated)
    }

    /** Parses the first revocation [PGPSignature] from armored input. */
    private fun loadRevocation(armored: ByteArray): PGPSignature =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            val factory = PGPObjectFactory(input, fingerprintCalculator)
            while (true) {
                when (val obj = factory.nextObject()) {
                    null -> break
                    is PGPSignature -> return obj
                    is PGPSignatureList -> return obj.first()
                    else -> Unit
                }
            }
            throw PgpException("Expected armored revocation signature")
        }

    private fun loadPublicRing(armored: ByteArray): PGPPublicKeyRing =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPPublicKeyRing
        }

    private fun loadSecretRing(armored: ByteArray): PGPSecretKeyRing =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }

    private fun armorPublicRing(ring: PGPPublicKeyRing): ByteArray =
        ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> ring.encode(armor) }
            out.toByteArray()
        }

    private fun armorSecretRing(ring: PGPSecretKeyRing): ByteArray =
        ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> ring.encode(armor) }
            out.toByteArray()
        }
}
