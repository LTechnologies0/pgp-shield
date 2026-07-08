package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP signature verification.
 *
 * Supports cleartext signed messages and detached signatures (text and binary),
 * resolving signer keys from provided public key rings.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.bouncycastle.bcpg.ArmoredInputStream
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/**
 * Input for signature verification.
 *
 * @property signedOrDetached Cleartext signed message or detached signature armor.
 * @property detachedMessage Original message when verifying a detached signature.
 * @property publicKeyRingsArmored Public key rings used to look up the signer.
 * @property binaryDocument When `true`, verify detached signatures over raw bytes (not canonical text).
 */
data class VerifyRequest(
    val signedOrDetached: ByteArray,
    val detachedMessage: ByteArray? = null,
    val publicKeyRingsArmored: List<ByteArray> = emptyList(),
    val binaryDocument: Boolean = false,
)

/**
 * Outcome of a verification attempt.
 *
 * @property valid `true` when the signature cryptographically verifies.
 * @property signerKeyId Key ID from the signature packet, if parsed.
 * @property message Canonical or original message bytes on success.
 * @property error Human-readable failure reason when [valid] is `false`.
 */
data class VerifyResult(
    val valid: Boolean,
    val signerKeyId: Long? = null,
    val message: ByteArray? = null,
    val error: String? = null,
)

/** Verifies OpenPGP cleartext and detached signatures. */
class PgpVerifier {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Verifies a cleartext signed message or detached signature per [request].
     *
     * Auto-detects cleartext armor; detached verification requires [VerifyRequest.detachedMessage].
     */
    fun verify(request: VerifyRequest): VerifyResult {
        val text = request.signedOrDetached.toString(Charsets.UTF_8)
        return when {
            text.contains("BEGIN PGP SIGNED MESSAGE") ->
                verifyCleartext(request.signedOrDetached, request.publicKeyRingsArmored)
            request.detachedMessage != null ->
                verifyDetached(
                    request.detachedMessage,
                    request.signedOrDetached,
                    request.publicKeyRingsArmored,
                    request.binaryDocument,
                )
            else -> VerifyResult(valid = false, error = "Not a cleartext signed message; provide message for detached verify")
        }
    }

    /** Verifies an inline cleartext signed message. */
    private fun verifyCleartext(armored: ByteArray, publicRings: List<ByteArray>): VerifyResult {
        return try {
            ArmoredInputStream(ByteArrayInputStream(armored)).use { armIn ->
                if (!armIn.isClearText) return VerifyResult(valid = false, error = "Not cleartext armor")
                val plainOut = ByteArrayOutputStream()
                var ch: Int
                while (armIn.read().also { ch = it } >= 0 && armIn.isClearText) {
                    plainOut.write(ch)
                }
                val canonical = plainOut.toByteArray()
                val sigList = PGPObjectFactory(armIn, fingerprintCalculator).nextObject() as PGPSignatureList
                val sig = sigList[0]
                val key = findPublicKey(sig.keyID, publicRings) ?: return VerifyResult(
                    valid = false,
                    signerKeyId = sig.keyID,
                    message = canonical,
                    error = "Signer key 0x${sig.keyID.toString(16)} not in keyring",
                )
                if (!verifySignature(sig, key, canonical)) {
                    return VerifyResult(valid = false, signerKeyId = sig.keyID, error = "Invalid signature")
                }
                VerifyResult(valid = true, signerKeyId = sig.keyID, message = canonical)
            }
        } catch (e: Exception) {
            VerifyResult(valid = false, error = e.message)
        }
    }

    /** Verifies a detached signature over [message]. */
    private fun verifyDetached(
        message: ByteArray,
        signatureArmored: ByteArray,
        publicRings: List<ByteArray>,
        binaryDocument: Boolean,
    ): VerifyResult {
        return try {
            PGPUtil.getDecoderStream(ByteArrayInputStream(signatureArmored)).use { sigStream ->
            val sigList = PGPObjectFactory(sigStream, fingerprintCalculator).nextObject() as PGPSignatureList
            val sig = sigList[0]
            val key = findPublicKey(sig.keyID, publicRings)
                ?: return VerifyResult(valid = false, signerKeyId = sig.keyID, error = "Signer key not in keyring")
            val data = if (binaryDocument) {
                message
            } else {
                canonicalize(message.toString(Charsets.UTF_8))
            }
            if (!verifySignature(sig, key, data)) {
                return VerifyResult(valid = false, signerKeyId = sig.keyID, error = "Invalid detached signature")
            }
            VerifyResult(valid = true, signerKeyId = sig.keyID, message = message)
            }
        } catch (e: Exception) {
            VerifyResult(valid = false, error = e.message)
        }
    }

    /** Initializes and runs signature verification, with BC/JCA operator fallback. */
    private fun verifySignature(sig: PGPSignature, key: PGPPublicKey, data: ByteArray): Boolean {
        val useBc = PgpOperators.useBcForPublicKey(key)
        return try {
            sig.init(PgpOperators.contentVerifierProvider(useBc), key)
            sig.update(data)
            sig.verify()
        } catch (_: Exception) {
            sig.init(PgpOperators.contentVerifierProvider(!useBc), key)
            sig.update(data)
            sig.verify()
        }
    }

    /** Looks up a public key by [keyId] across armored key rings. */
    private fun findPublicKey(keyId: Long, armoredRings: List<ByteArray>): PGPPublicKey? {
        for (armored in armoredRings) {
            val ring = readPublicRing(armored) ?: continue
            ring.getPublicKey(keyId)?.let { return it }
        }
        return null
    }

    private fun readPublicRing(armored: ByteArray): PGPPublicKeyRing? {
        return try {
            val input = PGPUtil.getDecoderStream(ByteArrayInputStream(armored))
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as? PGPPublicKeyRing
        } catch (_: Exception) {
            null
        }
    }

    /** Canonicalizes text per OpenPGP cleartext signature rules (CRLF, trailing spaces). */
    private fun canonicalize(text: String): ByteArray {
        var normalized = text.replace("\r\n", "\n").replace("\r", "\n")
        normalized = normalized.lines().joinToString("\n") { it.trimEnd() } + "\n"
        return normalized.toByteArray(Charsets.UTF_8)
    }
}
