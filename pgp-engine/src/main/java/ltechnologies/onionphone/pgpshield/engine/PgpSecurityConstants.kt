package ltechnologies.onionphone.pgpshield.engine

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags

/**
 * Cryptographic constants for secret-key packet construction and protection.
 *
 * Centralizes hash and symmetric algorithm choices used when binding subkeys,
 * computing secret-key checksums, and encrypting private key material. Values
 * follow RFC 4880 §5.5.3 and align with OpenKeychain's
 * [PgpSecurityConstants](https://github.com/open-keychain/open-keychain).
 */
object PgpSecurityConstants {
    /**
     * Fallback hash for subkey-binding signatures when curve-aware selection is
     * unavailable. Prefer [PgpAlgorithmPolicy.signatureHashForPublicKey] so
     * ECDSA P-384/P-521 bindings remain importable by GnuPG/Kleopatra.
     */
    const val SECRET_KEY_BINDING_SIGNATURE_HASH_ALGO = HashAlgorithmTags.SHA256

    /** Hash algorithm for the SHA-1 checksum appended to secret key packets. */
    const val SECRET_KEY_SIGNATURE_CHECKSUM_HASH_ALGO = HashAlgorithmTags.SHA1

    /**
     * Documented intent for secret-key S2K hash. Live encryptors still use SHA-1
     * (OpenPGP/S2K common practice via [PgpOperators.secretKeyEncryptor]); keep
     * this constant in sync if the encryptor switches digests.
     */
    const val SECRET_KEY_ENCRYPTOR_HASH_ALGO = HashAlgorithmTags.SHA1

    /** Symmetric cipher for passphrase-protected secret key packets. */
    const val SECRET_KEY_ENCRYPTOR_SYMMETRIC_ALGO = SymmetricKeyAlgorithmTags.AES_256

    /**
     * Encoded S2K iteration count (0–255) for secret-key protection.
     *
     * 255 ≈ 65 011 712 iterations — interoperable with GnuPG/OpenKeychain and
     * much stronger than BC's default 96 (65 536).
     */
    const val SECRET_KEY_ENCRYPTOR_S2K_COUNT = 255
}
