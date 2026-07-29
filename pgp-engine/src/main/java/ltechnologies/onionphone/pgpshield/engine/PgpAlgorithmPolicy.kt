package ltechnologies.onionphone.pgpshield.engine

/**
 * Cryptographic algorithm policy for the PGP engine.
 *
 * Defines allowed algorithms, default choices, platform-specific generation limits,
 * and validation rules applied to [ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo].
 */

import ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.Features
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator

/** Allowed algorithms, defaults, and key-ring validation for OpenPGP operations. */
object PgpAlgorithmPolicy {
    /** All BC-supported OpenPGP public-key algorithms (excl. experimental slots). */
    val allowedPublicKeyAlgorithms: Set<Int> = setOf(
        PublicKeyAlgorithmTags.RSA_GENERAL,
        PublicKeyAlgorithmTags.RSA_ENCRYPT,
        PublicKeyAlgorithmTags.RSA_SIGN,
        PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT,
        PublicKeyAlgorithmTags.ELGAMAL_GENERAL,
        PublicKeyAlgorithmTags.DSA,
        PublicKeyAlgorithmTags.EC,
        PublicKeyAlgorithmTags.ECDH,
        PublicKeyAlgorithmTags.ECDSA,
        PublicKeyAlgorithmTags.DIFFIE_HELLMAN,
        PublicKeyAlgorithmTags.EDDSA,
        PublicKeyAlgorithmTags.EDDSA_LEGACY,
        PublicKeyAlgorithmTags.X25519,
        PublicKeyAlgorithmTags.X448,
        PublicKeyAlgorithmTags.Ed25519,
        PublicKeyAlgorithmTags.Ed448,
        // ponytail: AEDH/AEDSA are BC reserved tags (import-only); no generators in BC 1.79 — skip KeyPairFactory until BC ships them.
        PublicKeyAlgorithmTags.AEDH,
        PublicKeyAlgorithmTags.AEDSA,
    )

    val allowedSymmetricAlgorithms: Set<Int> = setOf(
        SymmetricKeyAlgorithmTags.AES_128,
        SymmetricKeyAlgorithmTags.AES_192,
        SymmetricKeyAlgorithmTags.AES_256,
    )

    /** Default symmetric cipher for message encryption (AES-256). */
    val defaultSymmetricAlgorithm: Int = SymmetricKeyAlgorithmTags.AES_256

    /** Default hash algorithm for signatures and S2K. */
    val defaultHashAlgorithm: Int = HashAlgorithmTags.SHA256
    /** Minimum RSA modulus size accepted for generation and validation. */
    const val minRsaBits: Int = 2048

    /**
     * Selects the OpenPGP signature hash for [key].
     *
     * GnuPG, Kleopatra, and OpenKeychain reject ECDSA/DSA signatures whose digest
     * is shorter than the curve/group order (e.g. NIST P-521 with SHA-256 yields
     * "requires a 512 bit or larger hash" and the key is skipped on import).
     */
    fun signatureHashForPublicKey(key: PGPPublicKey): Int {
        val algorithm = key.algorithm
        val needsStrengthMatch =
            algorithm == PublicKeyAlgorithmTags.ECDSA ||
                algorithm == PublicKeyAlgorithmTags.EC ||
                algorithm == PublicKeyAlgorithmTags.DSA
        if (!needsStrengthMatch) return defaultHashAlgorithm
        val bits = key.bitStrength
        return when {
            bits >= 512 -> HashAlgorithmTags.SHA512
            bits >= 384 -> HashAlgorithmTags.SHA384
            else -> HashAlgorithmTags.SHA256
        }
    }
    /** RSA key sizes permitted for new key generation. */
    val allowedRsaBits: Set<Int> = setOf(2048, 3072, 4096)
    /** Default DSA primary key size for legacy DSA/ElGamal rings. */
    const val defaultDsaBits: Int = 3072
    /** Default ElGamal subkey size for legacy DSA/ElGamal rings. */
    const val defaultElGamalBits: Int = 3072

    /**
     * Preferred symmetric algorithms advertised on self-signatures (AES family only).
     *
     * Listed strongest-first so peers that honor preferences pick AES-256.
     */
    val preferredSymmetricAlgorithms: IntArray = intArrayOf(
        SymmetricKeyAlgorithmTags.AES_256,
        SymmetricKeyAlgorithmTags.AES_192,
        SymmetricKeyAlgorithmTags.AES_128,
    )

    /**
     * Preferred compression algorithms (uncompressed first — matches our encryptor).
     */
    val preferredCompressionAlgorithms: IntArray = intArrayOf(
        CompressionAlgorithmTags.UNCOMPRESSED,
        CompressionAlgorithmTags.ZIP,
        CompressionAlgorithmTags.ZLIB,
    )

    /**
     * Preferred hash algorithms for a signing [key], strongest/curve-safe first.
     *
     * Puts [signatureHashForPublicKey] first so ECDSA P-384/P-521 peers do not
     * fall back to an undersized digest.
     */
    fun preferredHashAlgorithms(key: PGPPublicKey): IntArray {
        val primary = signatureHashForPublicKey(key)
        val rest = intArrayOf(
            HashAlgorithmTags.SHA512,
            HashAlgorithmTags.SHA384,
            HashAlgorithmTags.SHA256,
        ).filter { it != primary }
        return (listOf(primary) + rest).toIntArray()
    }

    /**
     * Adds GnuPG/OpenKeychain-compatible preference and Features subpackets.
     *
     * Without these, GnuPG warns that AES-256 is "not found in recipient
     * preferences" and older encryptors may omit MDC.
     */
    fun applyInteropPreferences(hashed: PGPSignatureSubpacketGenerator, masterPublic: PGPPublicKey) {
        hashed.setPreferredSymmetricAlgorithms(false, preferredSymmetricAlgorithms)
        hashed.setPreferredHashAlgorithms(false, preferredHashAlgorithms(masterPublic))
        hashed.setPreferredCompressionAlgorithms(false, preferredCompressionAlgorithms)
        hashed.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION)
    }

    /**
     * Primary key types that can be generated on Android.
     *
     * DSA/ElGamal is excluded (Android JCA lacks ElGamal generation).
     * Ed448/X448 use OpenPGP algorithm tags 28/26 that GnuPG 2.4 and
     * OpenKeychain still skip on import — keep them off the UI.
     */
    val androidGeneratableKeyTypes: Set<KeyAlgorithmType> =
        KeyAlgorithmType.entries.toSet() -
            KeyAlgorithmType.DSA_ELGAMAL -
            KeyAlgorithmType.ED448

    /** Subkey types generatable on Android (excludes ElGamal and non-portable X448/Ed448). */
    val androidGeneratableSubkeyTypes: Set<SubkeyType> =
        SubkeyType.entries.toSet() -
            SubkeyType.ENCRYPT_ELGAMAL -
            SubkeyType.ENCRYPT_X448 -
            SubkeyType.SIGN_ED448 -
            SubkeyType.AUTH_ED448

    /**
     * Validates [info] against policy (algorithms, revocation).
     *
     * @param allowRevoked When `false`, revoked master or subkeys cause [PgpException].
     * @throws PgpException with [SecurityProblem] when validation fails.
     */
    fun validateKeyRing(info: KeyRingInfo, allowRevoked: Boolean = false) {
        if (!allowRevoked && info.isRevoked) throw PgpException("Key is revoked", SecurityProblem.REVOKED_KEY)
        for (subkey in info.subkeys) {
            if (subkey.algorithm !in allowedPublicKeyAlgorithms) {
                throw PgpException(
                    "Algorithm ${subkey.algorithm} not allowed",
                    SecurityProblem.INSECURE_ALGORITHM,
                )
            }
            if (!allowRevoked && subkey.isRevoked) {
                throw PgpException("Subkey revoked", SecurityProblem.REVOKED_KEY)
            }
        }
    }
}
