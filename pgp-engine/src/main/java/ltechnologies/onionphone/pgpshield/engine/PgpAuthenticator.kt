package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP authentication (GnuPG-style challenge signing with the AUTHENTICATION subkey).
 *
 * Signs an arbitrary challenge with the first secret subkey that carries the
 * [org.bouncycastle.bcpg.sig.KeyFlags.AUTHENTICATION] flag (falling back to a
 * signing-capable key). Used for identity proofs, SSH-agent-style challenges,
 * and service login flows that accept OpenPGP signatures.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/**
 * Request to authenticate a challenge string/bytes with an AUTHENTICATION-capable key.
 *
 * @property challenge Opaque challenge bytes (UTF-8 text or binary nonce).
 * @property secretKeyRingArmored Secret key ring containing an auth (or signing) subkey.
 * @property passphrase Passphrase unlocking the auth subkey.
 */
data class AuthenticateRequest(
    val challenge: ByteArray,
    val secretKeyRingArmored: ByteArray,
    val passphrase: CharArray,
)

/** Armored detached signature proving possession of the authentication key. */
data class AuthenticateResult(
    val signatureArmored: ByteArray,
    val keyId: Long,
    val fingerprint: String,
)

/**
 * Request to verify an authentication signature against a public key ring.
 */
data class VerifyAuthenticationRequest(
    val challenge: ByteArray,
    val signatureArmored: ByteArray,
    val publicKeyRingArmored: ByteArray,
)

/** Result of verifying an authentication signature. */
data class VerifyAuthenticationResult(
    val valid: Boolean,
    val signerKeyId: Long?,
)

/**
 * Produces and verifies OpenPGP authentication signatures (GnuPG `--authenticate` semantics).
 *
 * Uses [PGPSignature.BINARY_DOCUMENT] over the raw challenge with a key that has the
 * AUTHENTICATION key flag when available.
 */
class PgpAuthenticator {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /** Signs [AuthenticateRequest.challenge] with the authentication (or signing) subkey. */
    fun authenticate(request: AuthenticateRequest): AuthenticateResult {
        require(request.challenge.isNotEmpty()) { "Challenge must not be empty" }
        val secretRing = loadSecretRing(request.secretKeyRingArmored)
        val authKey = findAuthenticationSecretKey(secretRing)
        val publicKey = authKey.publicKey
        val useBc = PgpOperators.useBcForPublicKey(publicKey)
        val privateKey = PgpOperators.extractPrivateKey(authKey, request.passphrase)

        val sigGen = PGPSignatureGenerator(
            PgpOperators.contentSignerBuilder(publicKey.algorithm, useBc),
        )
        sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey)
        sigGen.update(request.challenge)
        val signature = sigGen.generate()

        val armored = ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> signature.encode(armor) }
            out.toByteArray()
        }
        return AuthenticateResult(
            signatureArmored = armored,
            keyId = publicKey.keyID,
            fingerprint = publicKey.fingerprint.joinToString("") { b -> "%02X".format(b) },
        )
    }

    /** Verifies that [VerifyAuthenticationRequest.signatureArmored] covers the challenge. */
    fun verify(request: VerifyAuthenticationRequest): VerifyAuthenticationResult {
        require(request.challenge.isNotEmpty()) { "Challenge must not be empty" }
        val publicRing = loadPublicRing(request.publicKeyRingArmored)
        val signature = loadSignature(request.signatureArmored)
            ?: return VerifyAuthenticationResult(valid = false, signerKeyId = null)

        val candidateKeys = collectVerificationKeys(publicRing, signature.keyID)
        for (pub in candidateKeys) {
            val useBc = PgpOperators.useBcForPublicKey(pub)
            signature.init(PgpOperators.contentVerifierProvider(useBc), pub)
            signature.update(request.challenge)
            if (signature.verify()) {
                return VerifyAuthenticationResult(valid = true, signerKeyId = pub.keyID)
            }
        }
        return VerifyAuthenticationResult(valid = false, signerKeyId = signature.keyID)
    }

    /** Prefers AUTHENTICATION-flagged subkeys, then any signing key, then master. */
    private fun findAuthenticationSecretKey(ring: PGPSecretKeyRing): PGPSecretKey {
        var auth: PGPSecretKey? = null
        var signing: PGPSecretKey? = null
        val iter = ring.secretKeys
        while (iter.hasNext()) {
            val sk = iter.next()
            val flags = readKeyFlags(sk.publicKey)
            if (flags and KeyFlags.AUTHENTICATION != 0 && !sk.isPrivateKeyEmpty) {
                auth = sk
                break
            }
            if (sk.isSigningKey && !sk.isPrivateKeyEmpty && signing == null) {
                signing = sk
            }
        }
        return auth ?: signing ?: ring.secretKey
    }

    private fun collectVerificationKeys(ring: PGPPublicKeyRing, preferredKeyId: Long): List<PGPPublicKey> {
        val keys = mutableListOf<PGPPublicKey>()
        val iter = ring.publicKeys
        while (iter.hasNext()) {
            val pk = iter.next()
            if (pk.keyID == preferredKeyId) keys.add(0, pk) else keys.add(pk)
        }
        // Prefer AUTHENTICATION-capable keys when scanning
        return keys.sortedByDescending { readKeyFlags(it) and KeyFlags.AUTHENTICATION }
    }

    private fun readKeyFlags(key: PGPPublicKey): Int {
        var flags = 0
        val sigs = key.signatures
        while (sigs.hasNext()) {
            val sig = sigs.next()
            val hashed = sig.hashedSubPackets ?: continue
            flags = flags or (hashed.getKeyFlags() ?: 0)
        }
        return flags
    }

    private fun loadSecretRing(armored: ByteArray): PGPSecretKeyRing =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }

    private fun loadPublicRing(armored: ByteArray): PGPPublicKeyRing =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPPublicKeyRing
        }

    private fun loadSignature(armored: ByteArray): PGPSignature? =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            val factory = PGPObjectFactory(input, fingerprintCalculator)
            when (val obj = factory.nextObject()) {
                is PGPSignatureList -> obj.get(0)
                is PGPSignature -> obj
                else -> null
            }
        }
}
