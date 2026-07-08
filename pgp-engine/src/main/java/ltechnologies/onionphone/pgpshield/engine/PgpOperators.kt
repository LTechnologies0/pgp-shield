package ltechnologies.onionphone.pgpshield.engine

/**
 * Factory for Bouncy Castle OpenPGP cryptographic operators.
 *
 * Selects between BC lightweight (`Bc*`) and JCA (`Jce*`) operator implementations
 * based on the public-key algorithm. BC lightweight operators must be paired with
 * `BcPGPKeyPair` material; JCA operators pair with `JcaPGPKeyPair`.
 */

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
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

    /** Returns a signature verifier provider matching the key material backend. */
    fun contentVerifierProvider(useBcLightweight: Boolean): PGPContentVerifierBuilderProvider =
        if (useBcLightweight) {
            BcPGPContentVerifierBuilderProvider()
        } else {
            JcaPGPContentVerifierBuilderProvider()
        }

    /**
     * Builds a passphrase encryptor for protecting secret key packets (AES-256, SHA-1 S2K).
     *
     * @param passphrase User passphrase; not copied or cleared by this method.
     * @param useBcLightweight Select BC or JCA encryptor implementation.
     */
    fun secretKeyEncryptor(passphrase: CharArray, useBcLightweight: Boolean): PBESecretKeyEncryptor {
        val digestCalc = JcaPlatform.digestCalculators.get(HashAlgorithmTags.SHA1)
        return if (useBcLightweight) {
            BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, digestCalc)
                .build(passphrase)
        } else {
            JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, digestCalc)
                .build(passphrase)
        }
    }

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
     * Unlocks a secret key with [passphrase], falling back to the alternate operator backend on failure.
     *
     * @throws Exception if both BC and JCA decryptors fail (wrong passphrase or corrupt packet).
     */
    fun extractPrivateKey(secretKey: PGPSecretKey, passphrase: CharArray): org.bouncycastle.openpgp.PGPPrivateKey {
        val preferBc = useBcForPublicKey(secretKey.publicKey)
        return try {
            secretKey.extractPrivateKey(secretKeyDecryptor(passphrase, preferBc))
        } catch (_: Exception) {
            secretKey.extractPrivateKey(secretKeyDecryptor(passphrase, !preferBc))
        }
    }
}
