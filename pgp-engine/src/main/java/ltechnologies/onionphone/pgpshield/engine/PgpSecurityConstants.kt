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
    /** Hash algorithm for subkey-binding and primary-key-binding signatures. */
    const val SECRET_KEY_BINDING_SIGNATURE_HASH_ALGO = HashAlgorithmTags.SHA256

    /** Hash algorithm for the SHA-1 checksum appended to secret key packets. */
    const val SECRET_KEY_SIGNATURE_CHECKSUM_HASH_ALGO = HashAlgorithmTags.SHA1

    /** Hash algorithm used by the secret-key encryptor (S2K / string-to-key). */
    const val SECRET_KEY_ENCRYPTOR_HASH_ALGO = HashAlgorithmTags.SHA256

    /** Symmetric cipher for passphrase-protected secret key packets. */
    const val SECRET_KEY_ENCRYPTOR_SYMMETRIC_ALGO = SymmetricKeyAlgorithmTags.AES_256
}
