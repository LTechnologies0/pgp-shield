package ltechnologies.onionphone.pgpshield.engine

/**
 * Human-readable labels for OpenPGP algorithms and key types.
 *
 * Used by the UI and logging to present algorithm names for raw algorithm tags,
 * [KeyAlgorithmType] presets, and [SubkeyType] variants.
 */

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags

/** Maps OpenPGP algorithm tags and key-type enums to display strings. */
object AlgorithmLabels {
    /**
     * Returns a short label for an OpenPGP public-key algorithm tag.
     *
     * @param algorithm Bouncy Castle `PublicKeyAlgorithmTags` value.
     * @param bits Optional key size in bits (e.g. RSA modulus length).
     */
    fun forAlgorithm(algorithm: Int, bits: Int? = null): String = when (algorithm) {
        PublicKeyAlgorithmTags.RSA_GENERAL,
        PublicKeyAlgorithmTags.RSA_ENCRYPT,
        PublicKeyAlgorithmTags.RSA_SIGN,
        -> bits?.let { "RSA $it" } ?: "RSA"
        PublicKeyAlgorithmTags.DSA -> bits?.let { "DSA $it" } ?: "DSA"
        PublicKeyAlgorithmTags.ELGAMAL_ENCRYPT,
        PublicKeyAlgorithmTags.ELGAMAL_GENERAL,
        -> bits?.let { "ElGamal $it" } ?: "ElGamal"
        PublicKeyAlgorithmTags.EDDSA,
        PublicKeyAlgorithmTags.EDDSA_LEGACY,
        PublicKeyAlgorithmTags.Ed25519,
        -> "Ed25519"
        PublicKeyAlgorithmTags.Ed448 -> "Ed448"
        PublicKeyAlgorithmTags.ECDH,
        PublicKeyAlgorithmTags.X25519,
        -> "ECDH"
        PublicKeyAlgorithmTags.X448 -> "X448"
        PublicKeyAlgorithmTags.ECDSA -> "ECDSA"
        PublicKeyAlgorithmTags.EC -> "EC"
        PublicKeyAlgorithmTags.DIFFIE_HELLMAN -> "DH"
        PublicKeyAlgorithmTags.AEDH -> "AEDH"
        PublicKeyAlgorithmTags.AEDSA -> "AEDSA"
        else -> "Algorithm $algorithm"
    }

    /** Describes a primary key algorithm preset including its default subkey layout. */
    fun forKeyType(type: KeyAlgorithmType, rsaBits: Int = 3072): String = when (type) {
        KeyAlgorithmType.RSA -> "RSA $rsaBits"
        KeyAlgorithmType.ED25519 -> "Ed25519 + Cv25519"
        KeyAlgorithmType.ED448 -> "Ed448 + X448"
        KeyAlgorithmType.ECDSA_P256 -> "ECDSA P-256 + ECDH P-256"
        KeyAlgorithmType.ECDSA_P384 -> "ECDSA P-384 + ECDH P-384"
        KeyAlgorithmType.ECDSA_P521 -> "ECDSA P-521 + ECDH P-521"
        KeyAlgorithmType.DSA_ELGAMAL -> "DSA + ElGamal"
    }

    /** User-facing label for key-generation UI option lists. */
    fun uiLabel(type: KeyAlgorithmType, rsaBits: Int = 3072): String = when (type) {
        KeyAlgorithmType.RSA -> "RSA $rsaBits"
        KeyAlgorithmType.ED25519 -> "ECC Curve25519 (Ed25519)"
        KeyAlgorithmType.ED448 -> "ECC Ed448"
        KeyAlgorithmType.ECDSA_P256 -> "ECC P-256"
        KeyAlgorithmType.ECDSA_P384 -> "ECC P-384"
        KeyAlgorithmType.ECDSA_P521 -> "ECC P-521"
        KeyAlgorithmType.DSA_ELGAMAL -> "DSA + ElGamal (legacy)"
    }

    /** Label for a subkey type when adding subkeys to an existing ring. */
    fun forSubkeyType(type: SubkeyType): String = when (type) {
        SubkeyType.ENCRYPT_RSA -> "RSA encrypt subkey"
        SubkeyType.SIGN_RSA -> "RSA sign subkey"
        SubkeyType.ENCRYPT_CV25519 -> "Cv25519 encrypt subkey"
        SubkeyType.ENCRYPT_X448 -> "X448 encrypt subkey"
        SubkeyType.ENCRYPT_ECDH_P256 -> "ECDH P-256 encrypt"
        SubkeyType.ENCRYPT_ECDH_P384 -> "ECDH P-384 encrypt"
        SubkeyType.ENCRYPT_ECDH_P521 -> "ECDH P-521 encrypt"
        SubkeyType.SIGN_ECDSA_P256 -> "ECDSA P-256 sign"
        SubkeyType.SIGN_ECDSA_P384 -> "ECDSA P-384 sign"
        SubkeyType.SIGN_ECDSA_P521 -> "ECDSA P-521 sign"
        SubkeyType.SIGN_ED25519 -> "Ed25519 sign subkey"
        SubkeyType.SIGN_ED448 -> "Ed448 sign subkey"
        SubkeyType.ENCRYPT_ELGAMAL -> "ElGamal encrypt subkey"
        SubkeyType.AUTH_RSA -> "RSA authentication subkey"
        SubkeyType.AUTH_ED25519 -> "Ed25519 authentication subkey"
        SubkeyType.AUTH_ED448 -> "Ed448 authentication subkey"
        SubkeyType.AUTH_ECDSA_P256 -> "ECDSA P-256 authentication"
        SubkeyType.AUTH_ECDSA_P384 -> "ECDSA P-384 authentication"
        SubkeyType.AUTH_ECDSA_P521 -> "ECDSA P-521 authentication"
    }
}

/**
 * Primary key algorithm presets for new OpenPGP key ring generation.
 *
 * Each type implies a signing primary plus matching encryption and authentication subkeys.
 */
enum class KeyAlgorithmType {
    RSA,
    ED25519,
    ED448,
    ECDSA_P256,
    ECDSA_P384,
    ECDSA_P521,
    DSA_ELGAMAL,
}
