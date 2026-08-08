package ltechnologies.onionphone.pgpshield.engine

/**
 * Factory for Bouncy Castle OpenPGP cryptographic operators.
 *
 * Selects between BC lightweight (`Bc*`) and JCA (`Jce*`) operator implementations
 * based on the public-key algorithm. BC lightweight operators must be paired with
 * `BcPGPKeyPair` material; JCA operators pair with `JcaPGPKeyPair`.
 */

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder

/** Shared operator builders for signing, verification, and secret-key encryption. */
object PgpOperators {
    private val bcVerifierProvider: PGPContentVerifierBuilderProvider =
        BcPGPContentVerifierBuilderProvider()
    private val jcaVerifierProvider: PGPContentVerifierBuilderProvider =
        JcaPGPContentVerifierBuilderProvider()

    /**
     * Returns a content signer builder for the given public-key algorithm.
     *
     * @param algorithm OpenPGP public-key algorithm tag.
     * @param useBcLightweight `true` for `BcPGPContentSignerBuilder`, `false` for JCA.
     * @param hashAlgorithm Hash algorithm tag for the signature (default SHA-256).
     */
    fun contentSignerBuilder(
        algorithm: Int,
        useBcLightweight: Boolean,
        hashAlgorithm: Int = HashAlgorithmTags.SHA256,
    ): PGPContentSignerBuilder =
        if (useBcLightweight) {
            BcPGPContentSignerBuilder(algorithm, hashAlgorithm)
        } else {
            JcaPGPContentSignerBuilder(algorithm, hashAlgorithm)
        }

    /**
     * Returns a content signer builder using a hash compatible with [publicKey].
     *
     * Prefer this over the algorithm-tag overload so ECDSA P-384/P-521 (and large
     * DSA) keys are not certified with an undersized digest that GnuPG rejects.
     */
    fun contentSignerBuilder(
        publicKey: PGPPublicKey,
        useBcLightweight: Boolean,
    ): PGPContentSignerBuilder =
        contentSignerBuilder(
            publicKey.algorithm,
            useBcLightweight,
            PgpAlgorithmPolicy.signatureHashForPublicKey(publicKey),
        )

    /** Returns a signature verifier provider matching the key material backend. */
    fun contentVerifierProvider(useBcLightweight: Boolean): PGPContentVerifierBuilderProvider =
        if (useBcLightweight) bcVerifierProvider else jcaVerifierProvider

    /**
     * Builds a passphrase encryptor for protecting secret key packets (AES-256, SHA-1 S2K).
     *
     * @param passphrase User passphrase; not copied or cleared by this method.
     * @param useBcLightweight Select BC or JCA encryptor implementation.
     */
    fun secretKeyEncryptor(passphrase: CharArray, useBcLightweight: Boolean): PBESecretKeyEncryptor {
        val digestCalc = JcaPlatform.digestCalculators.get(
            PgpSecurityConstants.SECRET_KEY_ENCRYPTOR_HASH_ALGO,
        )
        val encAlg = PgpSecurityConstants.SECRET_KEY_ENCRYPTOR_SYMMETRIC_ALGO
        val s2kCount = PgpSecurityConstants.SECRET_KEY_ENCRYPTOR_S2K_COUNT
        return if (useBcLightweight) {
            BcPBESecretKeyEncryptorBuilder(encAlg, digestCalc, s2kCount).build(passphrase)
        } else {
            JcePBESecretKeyEncryptorBuilder(encAlg, digestCalc, s2kCount).build(passphrase)
        }
    }

    /**
     * AEAD (Argon2) secret-key packet encryptor for v6-style protection.
     *
     * Requires the target key's [publicKey] packet (BC AEAD encryptor API).
     */
    fun aeadSecretKeyEncryptor(passphrase: CharArray, publicKey: PGPPublicKey): PBESecretKeyEncryptor =
        org.bouncycastle.openpgp.operator.bc.BcAEADSecretKeyEncryptorBuilder(
            org.bouncycastle.bcpg.AEADAlgorithmTags.OCB,
            PgpSecurityConstants.SECRET_KEY_ENCRYPTOR_SYMMETRIC_ALGO,
            org.bouncycastle.bcpg.S2K.Argon2Params.memoryConstrainedParameters(),
        )
            .setSecureRandom(SecureRandomProvider.secureRandom)
            .build(passphrase, publicKey.publicKeyPacket)

    /**
     * Builds a passphrase decryptor for unlocking secret key packets.
     *
     * @param passphrase User passphrase.
     * @param preferBc When `true`, try BC decryptor first.
     */
    fun secretKeyDecryptor(passphrase: CharArray, preferBc: Boolean): PBESecretKeyDecryptor {
        val digest = JcaPlatform.digestCalculators
        return if (preferBc) {
            BcPBESecretKeyDecryptorBuilder(digest).build(passphrase)
        } else {
            JcePBESecretKeyDecryptorBuilder(digest).build(passphrase)
        }
    }

    /** Returns whether BC lightweight operators should be used for [key]. */
    fun useBcForPublicKey(key: PGPPublicKey): Boolean =
        KeyPairFactory.useBcLightweight(key.algorithm)

    /** Converts OpenPGP key-flags bitmask into human-readable capability labels. */
    fun formatKeyFlags(flags: Int): List<String> = buildList {
        if (flags and KeyFlags.CERTIFY_OTHER != 0) add("Certify")
        if (flags and KeyFlags.SIGN_DATA != 0) add("Sign")
        if (flags and KeyFlags.ENCRYPT_COMMS != 0) add("Encrypt (comms)")
        if (flags and KeyFlags.ENCRYPT_STORAGE != 0) add("Encrypt (storage)")
        if (flags and KeyFlags.AUTHENTICATION != 0) add("Auth")
        if (isEmpty() && flags == 0) add("—")
    }

    /**
     * Unlocks a secret key with [passphrase].
     *
     * Tries the algorithm-matched backend first. Falls back to the alternate only when
     * the failure is **not** a passphrase checksum mismatch — wrong passphrase must not
     * pay a second full S2K (tens of millions of SHA-1 iterations).
     *
     * @throws Exception if both backends fail (or the first fails with wrong passphrase).
     */
    fun extractPrivateKey(secretKey: PGPSecretKey, passphrase: CharArray): org.bouncycastle.openpgp.PGPPrivateKey {
        val preferBc = useBcForPublicKey(secretKey.publicKey)
        val decryptors = buildList {
            // RFC 9580 / AEAD-protected secrets: prefer BC OpenPGP API decryptor.
            add {
                org.bouncycastle.openpgp.api.bc.BcOpenPGPImplementation()
                    .pbeSecretKeyDecryptorBuilderProvider()
                    .provide()
                    .build(passphrase)
            }
            add { secretKeyDecryptor(passphrase, preferBc) }
            add { secretKeyDecryptor(passphrase, !preferBc) }
        }
        var last: Exception? = null
        for (factory in decryptors) {
            try {
                return secretKey.extractPrivateKey(factory())
            } catch (e: Exception) {
                if (isPassphraseChecksumMismatch(e)) throw e
                last = e
            }
        }
        throw last ?: PgpException("Failed to unlock secret key")
    }

    /**
     * True when unlock failure indicates a wrong passphrase.
     *
     * Classic S2K: BC reports secret-key SHA-1 checksum mismatch.
     * AEAD (Argon2) secret protect: BC reports failure recovering AEAD-protected material.
     */
    fun isPassphraseChecksumMismatch(error: Throwable): Boolean {
        var cur: Throwable? = error
        while (cur != null) {
            val msg = cur.message.orEmpty()
            if (msg.contains("checksum mismatch", ignoreCase = true)) return true
            if (msg.contains("AEAD protected private key", ignoreCase = true)) return true
            if (msg.contains("recovering AEAD", ignoreCase = true)) return true
            cur = cur.cause
        }
        return false
    }
}
