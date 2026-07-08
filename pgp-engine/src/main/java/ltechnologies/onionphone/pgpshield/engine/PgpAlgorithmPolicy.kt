package ltechnologies.onionphone.pgpshield.engine

/**
 * Cryptographic algorithm policy for the PGP engine.
 *
 * Defines allowed algorithms, default choices, platform-specific generation limits,
 * and validation rules applied to [ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo].
 */

import ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags

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
    /** RSA key sizes permitted for new key generation. */
    val allowedRsaBits: Set<Int> = setOf(2048, 3072, 4096)
    /** Default DSA primary key size for legacy DSA/ElGamal rings. */
    const val defaultDsaBits: Int = 3072
    /** Default ElGamal subkey size for legacy DSA/ElGamal rings. */
    const val defaultElGamalBits: Int = 3072

    /**
     * Primary key types that can be generated on Android.
     *
     * DSA/ElGamal is excluded because the Android BC JCA provider lacks ElGamal key generation.
     */
    val androidGeneratableKeyTypes: Set<KeyAlgorithmType> =
        KeyAlgorithmType.entries.toSet() - KeyAlgorithmType.DSA_ELGAMAL

    /** Subkey types generatable on Android (excludes ElGamal encrypt subkeys). */
    val androidGeneratableSubkeyTypes: Set<SubkeyType> =
        SubkeyType.entries.toSet() - SubkeyType.ENCRYPT_ELGAMAL

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
