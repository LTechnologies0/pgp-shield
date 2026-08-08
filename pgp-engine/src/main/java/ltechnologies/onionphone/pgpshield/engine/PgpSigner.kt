package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP message signing.
 *
 * Produces cleartext signed messages or detached binary/text signatures using
 * the first signing-capable secret subkey in the ring.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Date
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPUtil

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
    /** When `true`, emit one-pass + literal + signature (binary document). */
    val inlineBinary: Boolean = false,
    /** When set and [SmartCardPort.ownsKey] for the signing key, sign via the card. */
    val smartCard: SmartCardPort? = null,
)

/** Armored signature output from [PgpSigner.sign]. */
data class SignResult(
    val output: ByteArray,
)

/** Signs messages and produces cleartext or detached OpenPGP signatures. */
class PgpSigner {
    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Signs [request.data] and returns armored output.
     *
     * Uses [SignRequest.detachedBinary] or cleartext mode based on flags.
     */
    fun sign(request: SignRequest): SignResult {
        CryptoProgress.stage(CryptoStage.PARSE_KEYS)
        val secretRing = PGPUtil.getDecoderStream(ByteArrayInputStream(request.secretKeyRingArmored)).use { input ->
            org.bouncycastle.openpgp.PGPObjectFactory(input, PgpFingerprints.calculator).nextObject() as PGPSecretKeyRing
        }
        val signingKey = findSigningSecretKey(secretRing)
        val useBc = PgpOperators.useBcForPublicKey(signingKey.publicKey)
        CryptoProgress.stage(CryptoStage.UNLOCK_SECRET)
        val card = request.smartCard?.takeIf { it.isAvailable() && it.ownsKey(signingKey.keyID) }
        val privateKey = if (card != null) {
            // Stub private key: key id + public packet only; material lives on the card.
            org.bouncycastle.openpgp.PGPPrivateKey(
                signingKey.keyID,
                signingKey.publicKey.publicKeyPacket,
                null,
            )
        } else {
            PgpOperators.extractPrivateKey(signingKey, request.passphrase)
        }
        val hashAlgorithm = PgpAlgorithmPolicy.signatureHashForPublicKey(signingKey.publicKey)

        CryptoProgress.stage(CryptoStage.SIGN)
        val signerBuilder = if (card != null) {
            SmartCardContentSignerBuilder(signingKey.publicKey, card, hashAlgorithm)
        } else {
            PgpOperators.contentSignerBuilder(signingKey.publicKey, useBc)
        }
        val sigGen = PGPSignatureGenerator(signerBuilder)
        if (request.inlineBinary) {
            val binary = buildInlineBinary(request.data, sigGen, privateKey)
            CryptoProgress.stage(CryptoStage.ARMOR)
            val armored = ByteArrayOutputStream().use { out ->
                ArmoredOutputStream(out).use { armor -> armor.write(binary) }
                out.toByteArray()
            }
            return SignResult(output = armored)
        }
        if (request.detachedBinary) {
            sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey)
            sigGen.update(request.data)
            val signature = sigGen.generate()
            CryptoProgress.stage(CryptoStage.ARMOR)
            val armored = ByteArrayOutputStream().use { out ->
                ArmoredOutputStream(out).use { armor -> signature.encode(armor) }
                out.toByteArray()
            }
            return SignResult(output = armored)
        }

        sigGen.init(PGPSignature.CANONICAL_TEXT_DOCUMENT, privateKey)

        // Hash CRLF-canonical text (no trailing CRLF after last line). Write LF
        // line endings in the armor body like GnuPG; verify re-canonicalizes.
        val hashed = PgpCleartext.canonicalize(request.data)
        sigGen.update(hashed)
        val signature = sigGen.generate()
        val display = PgpCleartext.displayForm(hashed)
        // Preserve a terminating newline in the cleartext section for readers.
        val displayWithNl = if (display.isEmpty() || display.last() == '\n'.code.toByte()) {
            display
        } else {
            display + "\n".toByteArray(Charsets.UTF_8)
        }

        val armored = ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor ->
                armor.beginClearText(hashAlgorithm)
                armor.write(displayWithNl)
                armor.endClearText()
                signature.encode(armor)
            }
            out.toByteArray()
        }
        return SignResult(output = armored)
    }

    /** One-pass signature packet + literal + signature (binary document). */
    private fun buildInlineBinary(
        data: ByteArray,
        sigGen: PGPSignatureGenerator,
        privateKey: PGPPrivateKey,
    ): ByteArray {
        sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey)
        return ByteArrayOutputStream().use { out ->
            sigGen.generateOnePassVersion(false).encode(out)
            val literalGen = PGPLiteralDataGenerator()
            literalGen.open(
                out,
                PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE,
                data.size.toLong(),
                Date(),
            ).use { literal ->
                literal.write(data)
                sigGen.update(data)
            }
            literalGen.close()
            sigGen.generate().encode(out)
            out.toByteArray()
        }
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
}
