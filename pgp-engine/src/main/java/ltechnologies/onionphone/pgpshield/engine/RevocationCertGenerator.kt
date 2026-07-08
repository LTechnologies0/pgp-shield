package ltechnologies.onionphone.pgpshield.engine

/**
 * Standalone OpenPGP key revocation certificate generation.
 *
 * Produces an armored key-revocation signature that can be distributed separately
 * from the secret key and applied later via [RevocationCertApplier].
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Date
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.sig.RevocationReasonTags
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/**
 * Parameters for generating a key revocation certificate.
 *
 * @property secretKeyRingArmored Secret key ring used to sign the revocation.
 * @property passphrase Passphrase to unlock the master secret key.
 * @property reason RFC 4880 revocation reason tag (default: no reason).
 * @property reasonText Optional human-readable revocation explanation.
 */
data class RevocationCertRequest(
    val secretKeyRingArmored: ByteArray,
    val passphrase: CharArray,
    val reason: Byte = RevocationReasonTags.NO_REASON,
    val reasonText: String = "",
)

/** Generates armored OpenPGP key revocation signatures from a secret key ring. */
class RevocationCertGenerator {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Signs a key-revocation certificate for the master key in [request].
     *
     * @return ASCII-armored revocation signature bytes.
     */
    fun generate(request: RevocationCertRequest): ByteArray {
        val secretRing = loadSecretRing(request.secretKeyRingArmored)
        val masterSecret = secretRing.secretKey
        val masterPublic = masterSecret.publicKey
        val useBc = PgpOperators.useBcForPublicKey(masterPublic)
        val privateKey = PgpOperators.extractPrivateKey(masterSecret, request.passphrase)
        val now = Date()

        val hashed = PGPSignatureSubpacketGenerator().apply {
            setRevocationReason(true, request.reason, request.reasonText)
            setSignatureCreationTime(true, now)
        }.generate()

        val sigGen = PGPSignatureGenerator(
            PgpOperators.contentSignerBuilder(masterPublic.algorithm, useBc),
        )
        sigGen.setHashedSubpackets(hashed)
        sigGen.init(PGPSignature.KEY_REVOCATION, privateKey)
        val revocation = sigGen.generateCertification(masterPublic)

        return ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> revocation.encode(armor) }
            out.toByteArray()
        }
    }

    /** Parses an armored secret key ring from bytes. */
    private fun loadSecretRing(armored: ByteArray): PGPSecretKeyRing =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }
}
