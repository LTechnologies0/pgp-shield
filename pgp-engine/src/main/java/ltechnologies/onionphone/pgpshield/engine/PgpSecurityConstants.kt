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
     * Documented fallback for classic Iterated+Salted S2K ([PgpOperators.secretKeyEncryptor]).
     * New v4/v6 secrets and subkeys default to Argon2+AEAD via
     * [PgpOperators.aeadSecretKeyEncryptor] (RFC 9580); this SHA-1 constant applies
     * only to the legacy encryptor path kept for interop / explicit opt-out.
     */
    const val SECRET_KEY_ENCRYPTOR_HASH_ALGO = HashAlgorithmTags.SHA1

    /** Symmetric cipher for passphrase-protected secret key packets. */
    const val SECRET_KEY_ENCRYPTOR_SYMMETRIC_ALGO = SymmetricKeyAlgorithmTags.AES_256

    /**
     * Encoded S2K iteration count (0–255) for secret-key protection.
     *
     * 208 ≈ 8 388 608 SHA-1 iterations. Mobile UX: elliptic-curve pairgen is ~50 ms;
     * S2K dominated keygen when run 3× sequentially at 255 (~65M). Still ~128× BC's
     * default 96 (65 536). Applies to **new** keys / passphrase rewraps only.
     *
     * RFC 4880 coded count: `(16 + (c & 15)) << ((c >> 4) + 6)`.
     */
    const val SECRET_KEY_ENCRYPTOR_S2K_COUNT = 208
}
