package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP message signing.
 *
 * Produces cleartext signed messages or detached binary/text signatures using
 * the first signing-capable secret subkey in the ring.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/**
 * Parameters for signing data with an OpenPGP secret key ring.
 *
 * @property data Payload to sign.
 * @property secretKeyRingArmored Secret key ring containing a signing subkey.
 * @property passphrase Passphrase to unlock the signing secret key.
 * @property cleartext When `true` (default), produce a cleartext signed message.
 * @property detachedBinary When `true`, emit a detached binary-document signature instead.
 */
data class SignRequest(
    val data: ByteArray,
    val secretKeyRingArmored: ByteArray,
    val passphrase: CharArray,
    val cleartext: Boolean = true,
    val detachedBinary: Boolean = false,
)

/** Armored signature output from [PgpSigner.sign]. */
data class SignResult(
    val output: ByteArray,
)

/** Signs messages and produces cleartext or detached OpenPGP signatures. */
class PgpSigner {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Signs [request.data] and returns armored output.
     *
     * Uses [SignRequest.detachedBinary] or cleartext mode based on flags.
     */
    fun sign(request: SignRequest): SignResult {
        val secretRing = PGPUtil.getDecoderStream(ByteArrayInputStream(request.secretKeyRingArmored)).use { input ->
            org.bouncycastle.openpgp.PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }
        val signingKey = findSigningSecretKey(secretRing)
        val useBc = PgpOperators.useBcForPublicKey(signingKey.publicKey)
        val privateKey = PgpOperators.extractPrivateKey(signingKey, request.passphrase)

        val sigGen = PGPSignatureGenerator(
            PgpOperators.contentSignerBuilder(signingKey.publicKey.algorithm, useBc),
        )
        if (request.detachedBinary) {
            sigGen.init(org.bouncycastle.openpgp.PGPSignature.BINARY_DOCUMENT, privateKey)
            sigGen.update(request.data)
            val signature = sigGen.generate()
            val armored = ByteArrayOutputStream().use { out ->
                ArmoredOutputStream(out).use { armor -> signature.encode(armor) }
                out.toByteArray()
            }
            return SignResult(output = armored)
        }

        sigGen.init(org.bouncycastle.openpgp.PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey)

        val canonical = canonicalizeCleartext(request.data)
        sigGen.update(canonical)
        val signature = sigGen.generate()

        val armored = ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor ->
                armor.beginClearText(HashAlgorithmTags.SHA256)
                armor.write(canonical)
                armor.endClearText()
                signature.encode(armor)
            }
            out.toByteArray()
        }
        return SignResult(output = armored)
    }

    /** Selects the first signing subkey, or falls back to the master key. */
    private fun findSigningSecretKey(ring: PGPSecretKeyRing): PGPSecretKey {
        val iter = ring.secretKeys
        while (iter.hasNext()) {
            val sk = iter.next()
            if (sk.isSigningKey) return sk
        }
        return ring.secretKey
    }

    /** Canonicalizes UTF-8 cleartext for OpenPGP text signatures. */
    private fun canonicalizeCleartext(data: ByteArray): ByteArray {
        var text = data.toString(Charsets.UTF_8).replace("\r\n", "\n").replace("\r", "\n")
        text = text.lines().joinToString("\n") { it.trimEnd() } + "\n"
        return text.toByteArray(Charsets.UTF_8)
    }
}
