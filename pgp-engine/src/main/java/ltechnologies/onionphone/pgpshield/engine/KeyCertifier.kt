package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP key certification (web of trust).
 *
 * Signs another user's public key with a certifier's secret key, producing an
 * updated armored public key ring with the new certification.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Date
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/**
 * Parameters for certifying a user ID on a target public key.
 *
 * @property certifierSecretArmored Certifier's secret key ring.
 * @property certifierPassphrase Passphrase for the certifier's signing key.
 * @property targetPublicArmored Target user's public key ring.
 * @property userId User ID on the target key to certify.
 * @property certificationType Trust level of the certification signature.
 */
data class CertifyKeyRequest(
    val certifierSecretArmored: ByteArray,
    val certifierPassphrase: CharArray,
    val targetPublicArmored: ByteArray,
    val userId: String,
    val certificationType: CertificationType = CertificationType.POSITIVE,
)

/** Armored public key ring including the new certification. */
data class CertifyKeyResult(
    val certifiedPublicArmored: ByteArray,
)

/** Certifies user IDs on third-party OpenPGP public keys. */
class KeyCertifier {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /** Signs [CertifyKeyRequest.userId] on the target key with the requested certification type. */
    fun certify(request: CertifyKeyRequest): CertifyKeyResult {
        require(request.userId.isNotBlank()) { "User ID must not be blank" }
        val certifierRing = loadSecretRing(request.certifierSecretArmored)
        val certifierSecret = findSigningSecretKey(certifierRing)
        val certifierPublic = certifierSecret.publicKey
        val useBc = PgpOperators.useBcForPublicKey(certifierPublic)
        val certifierPrivate = PgpOperators.extractPrivateKey(certifierSecret, request.certifierPassphrase)

        val targetRing = loadPublicRing(request.targetPublicArmored)
        val targetKey = targetRing.publicKey
        require(userIdExists(targetKey, request.userId)) { "User ID not found on target key" }

        val now = Date()
        val hashed = PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(true, now)
        }.generate()

        val sigGen = PGPSignatureGenerator(
            PgpOperators.contentSignerBuilder(certifierPublic.algorithm, useBc),
        )
        sigGen.setHashedSubpackets(hashed)
        sigGen.init(request.certificationType.toSignatureType(), certifierPrivate)
        val cert = sigGen.generateCertification(request.userId, targetKey)
        val certified = PGPPublicKey.addCertification(targetKey, request.userId, cert)
        val updatedRing = replaceMasterKeyInRing(targetRing, certified)

        return CertifyKeyResult(
            certifiedPublicArmored = ByteArrayOutputStream().use { out ->
                ArmoredOutputStream(out).use { armor -> updatedRing.encode(armor) }
                out.toByteArray()
            },
        )
    }

    /** Returns whether [userId] is bound to [key]. */
    private fun userIdExists(key: PGPPublicKey, userId: String): Boolean {
        val ids = key.userIDs
        while (ids.hasNext()) {
            if (ids.next().toString() == userId) return true
        }
        return false
    }

    /** Picks the first signing subkey in [ring], or the master key. */
    private fun findSigningSecretKey(ring: PGPSecretKeyRing): PGPSecretKey {
        val iter = ring.secretKeys
        while (iter.hasNext()) {
            val sk = iter.next()
            if (sk.isSigningKey) return sk
        }
        return ring.secretKey
    }

    private fun loadSecretRing(armored: ByteArray): PGPSecretKeyRing =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }

    private fun loadPublicRing(armored: ByteArray): PGPPublicKeyRing =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPPublicKeyRing
        }
}
