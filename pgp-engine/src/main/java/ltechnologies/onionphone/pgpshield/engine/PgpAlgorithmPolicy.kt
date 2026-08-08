package ltechnologies.onionphone.pgpshield.engine

/**
 * Cryptographic algorithm policy for the PGP engine.
 *
 * Defines allowed algorithms, default choices, platform-specific generation limits,
 * and validation rules applied to [ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo].
 */

import ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo
import org.bouncycastle.bcpg.AEADAlgorithmTags
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.bcpg.sig.Features
import org.bouncycastle.bcpg.sig.PreferredAEADCiphersuites
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator

/** Allowed algorithms, defaults, and key-ring validation for OpenPGP operations. */
object PgpAlgorithmPolicy {
    /** Allowed OpenPGP public-key algorithms for import / trust (excl. unused experimental). */
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
        PublicKeyAlgorithmTags.EDDSA,
        PublicKeyAlgorithmTags.EDDSA_LEGACY,
        PublicKeyAlgorithmTags.X25519,
        PublicKeyAlgorithmTags.X448,
        PublicKeyAlgorithmTags.Ed25519,
        PublicKeyAlgorithmTags.Ed448,
        // DIFFIE_HELLMAN / AEDH / AEDSA: not accepted for trust (no generators; experimental).
    )

    /** Curve OIDs accepted for ECDSA/ECDH/EC import (NIST + Brainpool r1 + Curve25519/448). */
    val allowedEccCurveOids: Set<String> = setOf(
        "1.2.840.10045.3.1.7", // NIST P-256
        "1.3.132.0.34", // NIST P-384
        "1.3.132.0.35", // NIST P-521
        "1.3.36.3.3.2.8.1.1.7", // brainpoolP256r1
        "1.3.36.3.3.2.8.1.1.11", // brainpoolP384r1
        "1.3.36.3.3.2.8.1.1.13", // brainpoolP512r1
        "1.3.6.1.4.1.3029.1.5.1", // Curve25519 (GNU / legacy ECDH)
        "1.3.101.110", // X25519 (RFC 8410)
        "1.3.101.111", // X448
        "1.3.101.112", // Ed25519
        "1.3.101.113", // Ed448
    )

    val allowedSymmetricAlgorithms: Set<Int> = setOf(
        SymmetricKeyAlgorithmTags.AES_128,
        SymmetricKeyAlgorithmTags.AES_192,
        SymmetricKeyAlgorithmTags.AES_256,
        SymmetricKeyAlgorithmTags.CAMELLIA_128,
        SymmetricKeyAlgorithmTags.CAMELLIA_192,
        SymmetricKeyAlgorithmTags.CAMELLIA_256,
        SymmetricKeyAlgorithmTags.TWOFISH,
    )

    /** Default symmetric cipher for message encryption (AES-256). */
    val defaultSymmetricAlgorithm: Int = SymmetricKeyAlgorithmTags.AES_256

    /** Default AEAD mode for SEIPDv2 message encryption (OCB). */
    val defaultAeadAlgorithm: Int = AEADAlgorithmTags.OCB

    /** Default hash algorithm for signatures and S2K. */
    val defaultHashAlgorithm: Int = HashAlgorithmTags.SHA256
    /** Minimum RSA modulus size accepted for generation and validation. */
    const val minRsaBits: Int = 2048
    /** Minimum DSA group size accepted on import (generation already disabled). */
    const val minDsaBits: Int = 2048
    /** Minimum ElGamal modulus size accepted on import (generation already disabled). */
    const val minElGamalBits: Int = 2048

    /**
     * Hash algorithms accepted when verifying signatures (sign path already uses ≥SHA-256).
     * Rejects MD5 / SHA-1 / RIPEMD160.
     */
    val allowedHashAlgorithms: Set<Int> = setOf(
        HashAlgorithmTags.SHA256,
        HashAlgorithmTags.SHA384,
        HashAlgorithmTags.SHA512,
        HashAlgorithmTags.SHA3_256,
        HashAlgorithmTags.SHA3_512,
    )

    /**
     * Compression algorithms accepted when decrypting messages.
     */
    val allowedCompressionAlgorithms: Set<Int> = setOf(
        CompressionAlgorithmTags.UNCOMPRESSED,
        CompressionAlgorithmTags.ZIP,
        CompressionAlgorithmTags.ZLIB,
        CompressionAlgorithmTags.BZIP2,
    )

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

    /**
     * Rejects signature digests that are shorter than the key's curve/group order
     * (same thresholds as [signatureHashForPublicKey]).
     */
    fun requireHashStrengthForKey(key: PGPPublicKey, hashAlgorithm: Int) {
        requireAllowedHash(hashAlgorithm)
        val required = signatureHashForPublicKey(key)
        val needsStrengthMatch =
            key.algorithm == PublicKeyAlgorithmTags.ECDSA ||
                key.algorithm == PublicKeyAlgorithmTags.EC ||
                key.algorithm == PublicKeyAlgorithmTags.DSA
        if (!needsStrengthMatch) return
        val strength = hashDigestBits(hashAlgorithm)
        val requiredBits = hashDigestBits(required)
        if (strength < requiredBits) {
            throw PgpException(
                "Hash algorithm $hashAlgorithm too weak for key (${key.bitStrength} bits; need ≥$requiredBits-bit digest)",
                SecurityProblem.INSECURE_ALGORITHM,
            )
        }
    }

    private fun hashDigestBits(hashAlgorithm: Int): Int = when (hashAlgorithm) {
        HashAlgorithmTags.SHA256, HashAlgorithmTags.SHA3_256 -> 256
        HashAlgorithmTags.SHA384 -> 384
        HashAlgorithmTags.SHA512, HashAlgorithmTags.SHA3_512 -> 512
        else -> 0
    }
    /** RSA key sizes permitted for new key generation. */
    val allowedRsaBits: Set<Int> = setOf(2048, 3072, 4096)
    /** Default DSA primary key size for legacy DSA/ElGamal rings. */
    const val defaultDsaBits: Int = 3072
    /** Default ElGamal subkey size for legacy DSA/ElGamal rings. */
    const val defaultElGamalBits: Int = 3072

    /**
     * Preferred symmetric algorithms advertised on self-signatures.
     *
     * AES first (interop), then Camellia / Twofish for BC-capable peers.
     */
    val preferredSymmetricAlgorithms: IntArray = intArrayOf(
        SymmetricKeyAlgorithmTags.AES_256,
        SymmetricKeyAlgorithmTags.AES_192,
        SymmetricKeyAlgorithmTags.AES_128,
        SymmetricKeyAlgorithmTags.CAMELLIA_256,
        SymmetricKeyAlgorithmTags.CAMELLIA_192,
        SymmetricKeyAlgorithmTags.CAMELLIA_128,
        SymmetricKeyAlgorithmTags.TWOFISH,
    )

    /**
     * Preferred AEAD ciphersuites (RFC 9580 Preferred AEAD Ciphersuites).
     */
    val preferredAeadCiphersuites: Array<PreferredAEADCiphersuites.Combination> = arrayOf(
        PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.OCB),
        PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_256, AEADAlgorithmTags.GCM),
        PreferredAEADCiphersuites.Combination(SymmetricKeyAlgorithmTags.AES_128, AEADAlgorithmTags.OCB),
    )

    /**
     * Preferred compression algorithms (uncompressed first — matches default encryptor).
     */
    val preferredCompressionAlgorithms: IntArray = intArrayOf(
        CompressionAlgorithmTags.UNCOMPRESSED,
        CompressionAlgorithmTags.ZIP,
        CompressionAlgorithmTags.ZLIB,
        CompressionAlgorithmTags.BZIP2,
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
            HashAlgorithmTags.SHA3_512,
            HashAlgorithmTags.SHA3_256,
        ).filter { it != primary }
        return (listOf(primary) + rest).toIntArray()
    }

    /**
     * Adds GnuPG/OpenKeychain-compatible preference and Features subpackets.
     *
     * Without these, GnuPG warns that AES-256 is "not found in recipient
     * preferences" and older encryptors may omit MDC. Also advertises AEAD /
     * SEIPDv2 for RFC 9580 peers.
     */
    fun applyInteropPreferences(hashed: PGPSignatureSubpacketGenerator, masterPublic: PGPPublicKey) {
        hashed.setPreferredSymmetricAlgorithms(false, preferredSymmetricAlgorithms)
        hashed.setPreferredHashAlgorithms(false, preferredHashAlgorithms(masterPublic))
        hashed.setPreferredCompressionAlgorithms(false, preferredCompressionAlgorithms)
        hashed.setPreferredAEADCiphersuites(false, preferredAeadCiphersuites)
        val featureBits =
            Features.FEATURE_MODIFICATION_DETECTION.toInt() or
                Features.FEATURE_AEAD_ENCRYPTED_DATA.toInt() or
                Features.FEATURE_SEIPD_V2.toInt()
        hashed.setFeature(false, featureBits.toByte())
    }

    /**
     * Primary key types offered in the Android create-key UI.
     *
     * DSA/ElGamal remain importable ([allowedPublicKeyAlgorithms]) but are not generatable —
     * RFC 9580 treats them as legacy; new rings should use Ed25519/X25519, NIST EC, or RSA≥2048.
     */
    val androidGeneratableKeyTypes: Set<KeyAlgorithmType> =
        KeyAlgorithmType.entries.filter { it != KeyAlgorithmType.DSA_ELGAMAL }.toSet()

    /**
     * Subkey types offered when adding a subkey on Android.
     * ElGamal encrypt subkeys are import-only (legacy DSA/ElGamal rings).
     */
    val androidGeneratableSubkeyTypes: Set<SubkeyType> =
        SubkeyType.entries.filter { it != SubkeyType.ENCRYPT_ELGAMAL }.toSet()

    /**
     * Rejects disallowed message symmetric algorithms (decrypt / policy gate).
     *
     * @throws PgpException [SecurityProblem.INSECURE_ALGORITHM] when [algorithm] is known and not allowed.
     */
    fun requireAllowedSymmetric(algorithm: Int) {
        // 0 / NULL = not yet reported by BC for some packet shapes — skip until known.
        if (algorithm == SymmetricKeyAlgorithmTags.NULL || algorithm == 0) return
        if (algorithm !in allowedSymmetricAlgorithms) {
            throw PgpException(
                "Symmetric algorithm $algorithm is not allowed",
                SecurityProblem.INSECURE_ALGORITHM,
            )
        }
    }

    /**
     * Rejects disallowed signature hash algorithms (verify / one-pass gate).
     *
     * @throws PgpException [SecurityProblem.INSECURE_ALGORITHM] when [algorithm] is not allowed.
     */
    fun requireAllowedHash(algorithm: Int) {
        if (algorithm !in allowedHashAlgorithms) {
            throw PgpException(
                "Hash algorithm $algorithm is not allowed",
                SecurityProblem.INSECURE_ALGORITHM,
            )
        }
    }

    /**
     * Rejects disallowed compression algorithms on the decrypt path.
     *
     * @throws PgpException [SecurityProblem.INSECURE_ALGORITHM] when [algorithm] is not allowed.
     */
    fun requireAllowedCompression(algorithm: Int) {
        if (algorithm !in allowedCompressionAlgorithms) {
            throw PgpException(
                "Compression algorithm $algorithm is not allowed",
                SecurityProblem.INSECURE_ALGORITHM,
            )
        }
    }

    /**
     * Subkey types ordered for UI when adding to a ring whose master uses [masterAlgorithm].
     *
     * Matching family first (RSA→RSA, Ed25519→Cv25519/Ed25519, ECDSA→NIST then Brainpool),
     * then the remaining [androidGeneratableSubkeyTypes]. OpenPGP allows mixed algorithms;
     * this only sets defaults and menu order, not a hard restriction.
     */
    fun preferredSubkeyTypesForMaster(masterAlgorithm: Int): List<SubkeyType> {
        val matching = matchingSubkeyTypesForMaster(masterAlgorithm)
            .filter { it in androidGeneratableSubkeyTypes }
        val rest = androidGeneratableSubkeyTypes.filter { it !in matching }
        return matching + rest
    }

    /** Default encrypt-oriented subkey type matching the master's algorithm family. */
    fun defaultSubkeyTypeForMaster(masterAlgorithm: Int): SubkeyType =
        preferredSubkeyTypesForMaster(masterAlgorithm).first()

    private fun matchingSubkeyTypesForMaster(masterAlgorithm: Int): List<SubkeyType> =
        when (masterAlgorithm) {
            PublicKeyAlgorithmTags.RSA_GENERAL,
            PublicKeyAlgorithmTags.RSA_ENCRYPT,
            PublicKeyAlgorithmTags.RSA_SIGN,
            -> listOf(
                SubkeyType.ENCRYPT_RSA,
                SubkeyType.SIGN_RSA,
                SubkeyType.AUTH_RSA,
            )
            PublicKeyAlgorithmTags.EDDSA,
            PublicKeyAlgorithmTags.EDDSA_LEGACY,
            PublicKeyAlgorithmTags.Ed25519,
            PublicKeyAlgorithmTags.X25519,
            -> listOf(
                SubkeyType.ENCRYPT_CV25519,
                SubkeyType.SIGN_ED25519,
                SubkeyType.AUTH_ED25519,
            )
            PublicKeyAlgorithmTags.Ed448,
            PublicKeyAlgorithmTags.X448,
            -> listOf(
                SubkeyType.ENCRYPT_X448,
                SubkeyType.SIGN_ED448,
                SubkeyType.AUTH_ED448,
            )
            PublicKeyAlgorithmTags.ECDSA,
            PublicKeyAlgorithmTags.ECDH,
            PublicKeyAlgorithmTags.EC,
            -> listOf(
                SubkeyType.ENCRYPT_ECDH_P256,
                SubkeyType.SIGN_ECDSA_P256,
                SubkeyType.AUTH_ECDSA_P256,
                SubkeyType.ENCRYPT_ECDH_P384,
                SubkeyType.SIGN_ECDSA_P384,
                SubkeyType.AUTH_ECDSA_P384,
                SubkeyType.ENCRYPT_ECDH_P521,
                SubkeyType.SIGN_ECDSA_P521,
                SubkeyType.AUTH_ECDSA_P521,
                SubkeyType.ENCRYPT_ECDH_BRAINPOOL_P256R1,
                SubkeyType.SIGN_ECDSA_BRAINPOOL_P256R1,
                SubkeyType.AUTH_ECDSA_BRAINPOOL_P256R1,
                SubkeyType.ENCRYPT_ECDH_BRAINPOOL_P384R1,
                SubkeyType.SIGN_ECDSA_BRAINPOOL_P384R1,
                SubkeyType.AUTH_ECDSA_BRAINPOOL_P384R1,
                SubkeyType.ENCRYPT_ECDH_BRAINPOOL_P512R1,
                SubkeyType.SIGN_ECDSA_BRAINPOOL_P512R1,
                SubkeyType.AUTH_ECDSA_BRAINPOOL_P512R1,
            )
            PublicKeyAlgorithmTags.DSA,
            PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT,
            PublicKeyAlgorithmTags.ELGAMAL_GENERAL,
            -> listOf(
                // ElGamal encrypt remains preferred for imported DSA/ElGamal masters,
                // but is not in androidGeneratableSubkeyTypes (import/legacy only).
                SubkeyType.ENCRYPT_ELGAMAL,
                SubkeyType.ENCRYPT_RSA,
                SubkeyType.SIGN_RSA,
                SubkeyType.AUTH_RSA,
            )
            else -> listOf(
                SubkeyType.ENCRYPT_CV25519,
                SubkeyType.SIGN_ED25519,
                SubkeyType.AUTH_ED25519,
            )
        }

    /**
     * Validates [info] against policy (algorithms, RSA strength, revocation, expiry).
     *
     * @param allowRevoked When `false`, revoked master or subkeys cause [PgpException].
     * @param allowExpired When `false`, expired master or subkeys cause [PgpException].
     * @throws PgpException with [SecurityProblem] when validation fails.
     */
    fun validateKeyRing(
        info: KeyRingInfo,
        allowRevoked: Boolean = false,
        allowExpired: Boolean = false,
    ) {
        if (!allowRevoked && info.isRevoked) throw PgpException("Key is revoked", SecurityProblem.REVOKED_KEY)
        val now = java.time.Instant.now()
        for (subkey in info.subkeys) {
            if (subkey.algorithm !in allowedPublicKeyAlgorithms) {
                throw PgpException(
                    "Algorithm ${subkey.algorithm} not allowed",
                    SecurityProblem.INSECURE_ALGORITHM,
                )
            }
            if (isRsaAlgorithm(subkey.algorithm)) {
                if (subkey.bitStrength <= 0 || subkey.bitStrength < minRsaBits) {
                    throw PgpException(
                        "RSA key too weak or unknown strength (${subkey.bitStrength} bits; minimum $minRsaBits)",
                        SecurityProblem.INSECURE_ALGORITHM,
                    )
                }
            }
            if (isDsaAlgorithm(subkey.algorithm)) {
                if (subkey.bitStrength <= 0 || subkey.bitStrength < minDsaBits) {
                    throw PgpException(
                        "DSA key too weak or unknown strength (${subkey.bitStrength} bits; minimum $minDsaBits)",
                        SecurityProblem.INSECURE_ALGORITHM,
                    )
                }
            }
            if (isElGamalAlgorithm(subkey.algorithm)) {
                if (subkey.bitStrength <= 0 || subkey.bitStrength < minElGamalBits) {
                    throw PgpException(
                        "ElGamal key too weak or unknown strength (${subkey.bitStrength} bits; minimum $minElGamalBits)",
                        SecurityProblem.INSECURE_ALGORITHM,
                    )
                }
            }
            if (isClassicEccAlgorithm(subkey.algorithm)) {
                val oid = subkey.curveOid
                if (oid.isNullOrBlank() || oid !in allowedEccCurveOids) {
                    throw PgpException(
                        "ECC curve not allowed (${oid ?: "unknown"})",
                        SecurityProblem.INSECURE_ALGORITHM,
                    )
                }
            }
            if (!allowRevoked && subkey.isRevoked) {
                throw PgpException("Subkey revoked", SecurityProblem.REVOKED_KEY)
            }
            if (!allowExpired) {
                val exp = subkey.expirationTime
                if (exp != null && !exp.isAfter(now)) {
                    throw PgpException("Key expired", SecurityProblem.EXPIRED_KEY)
                }
            }
        }
    }

    private fun isRsaAlgorithm(algorithm: Int): Boolean =
        algorithm == PublicKeyAlgorithmTags.RSA_GENERAL ||
            algorithm == PublicKeyAlgorithmTags.RSA_ENCRYPT ||
            algorithm == PublicKeyAlgorithmTags.RSA_SIGN

    private fun isDsaAlgorithm(algorithm: Int): Boolean =
        algorithm == PublicKeyAlgorithmTags.DSA

    private fun isElGamalAlgorithm(algorithm: Int): Boolean =
        algorithm == PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT ||
            algorithm == PublicKeyAlgorithmTags.ELGAMAL_GENERAL

    private fun isClassicEccAlgorithm(algorithm: Int): Boolean =
        algorithm == PublicKeyAlgorithmTags.EC ||
            algorithm == PublicKeyAlgorithmTags.ECDH ||
            algorithm == PublicKeyAlgorithmTags.ECDSA
}
