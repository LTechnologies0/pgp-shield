package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP key-pair generation for primary keys and subkeys.
 *
 * Routes each [KeyAlgorithmType] and [SubkeyType] to the correct backend:
 * JCA platform crypto for RSA/DSA/ElGamal, BC lightweight for Ed25519/Ed448/X25519/X448
 * and NIST elliptic curves. Also exposes [useBcLightweight] for operator selection.
 */

import java.util.Date
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPublicKey

/** Factory that produces algorithm-specific signing, encryption, and authentication key pairs. */
object KeyPairFactory {
    /**
     * A generated OpenPGP key pair plus a flag indicating which operator backend to use.
     *
     * @property pair BC or JCA `PGPKeyPair` ready for ring construction.
     * @property useBcLightweight `true` when BC lightweight operators must be used.
     */
    data class Generated(val pair: PGPKeyPair, val useBcLightweight: Boolean)

    /** Creates the master signing (certify + sign) key pair for a new key ring. */
    fun masterSigningPair(type: KeyAlgorithmType, rsaBits: Int, date: Date): Generated = when (type) {
        KeyAlgorithmType.RSA -> Generated(JcaPlatform.rsaSignMasterPair(rsaBits, date), false)
        KeyAlgorithmType.ED25519 -> BcKeyPairs.ed25519(date).let { Generated(it.pair, true) }
        KeyAlgorithmType.ED448 -> BcKeyPairs.ed448(date).let { Generated(it.pair, true) }
        KeyAlgorithmType.ECDSA_P256 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P256, date), true)
        KeyAlgorithmType.ECDSA_P384 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P384, date), true)
        KeyAlgorithmType.ECDSA_P521 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P521, date), true)
        KeyAlgorithmType.DSA_ELGAMAL -> Generated(JcaPlatform.dsaKeyPair(PgpAlgorithmPolicy.defaultDsaBits, date), false)
    }

    /** Creates the encryption subkey pair paired with the given primary algorithm type. */
    fun encryptionSubkeyPair(type: KeyAlgorithmType, rsaBits: Int, date: Date): Generated = when (type) {
        KeyAlgorithmType.RSA -> Generated(JcaPlatform.rsaEncryptSubPair(rsaBits, date), false)
        KeyAlgorithmType.ED25519 -> BcKeyPairs.x25519(date).let { Generated(it.pair, true) }
        KeyAlgorithmType.ED448 -> BcKeyPairs.x448(date).let { Generated(it.pair, true) }
        KeyAlgorithmType.ECDSA_P256 -> Generated(BcEcKeyPairs.ecdh(EccCurve.P256, date), true)
        KeyAlgorithmType.ECDSA_P384 -> Generated(BcEcKeyPairs.ecdh(EccCurve.P384, date), true)
        KeyAlgorithmType.ECDSA_P521 -> Generated(BcEcKeyPairs.ecdh(EccCurve.P521, date), true)
        KeyAlgorithmType.DSA_ELGAMAL -> Generated(
            JcaPlatform.elGamalKeyPair(PgpAlgorithmPolicy.defaultElGamalBits, date),
            false,
        )
    }

    /**
     * Creates an authentication subkey (sign-capable material with authentication flag only).
     */
    fun authenticationSubkeyPair(type: KeyAlgorithmType, rsaBits: Int, date: Date): Generated = when (type) {
        KeyAlgorithmType.RSA -> Generated(JcaPlatform.rsaSignMasterPair(rsaBits, date), false)
        KeyAlgorithmType.ED25519 -> BcKeyPairs.ed25519(date).let { Generated(it.pair, true) }
        KeyAlgorithmType.ED448 -> BcKeyPairs.ed448(date).let { Generated(it.pair, true) }
        KeyAlgorithmType.ECDSA_P256 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P256, date), true)
        KeyAlgorithmType.ECDSA_P384 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P384, date), true)
        KeyAlgorithmType.ECDSA_P521 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P521, date), true)
        KeyAlgorithmType.DSA_ELGAMAL -> Generated(JcaPlatform.dsaKeyPair(PgpAlgorithmPolicy.defaultDsaBits, date), false)
    }

    /** Creates a key pair for an explicit [SubkeyType] when adding subkeys to an existing ring. */
    fun pairForSubkeyType(subkey: SubkeyType, rsaBits: Int, date: Date): Generated = when (subkey) {
        SubkeyType.ENCRYPT_RSA -> Generated(JcaPlatform.rsaEncryptSubPair(rsaBits, date), false)
        SubkeyType.SIGN_RSA -> Generated(JcaPlatform.rsaSignMasterPair(rsaBits, date), false)
        SubkeyType.ENCRYPT_CV25519 -> BcKeyPairs.x25519(date).let { Generated(it.pair, true) }
        SubkeyType.ENCRYPT_X448 -> BcKeyPairs.x448(date).let { Generated(it.pair, true) }
        SubkeyType.ENCRYPT_ECDH_P256 -> Generated(BcEcKeyPairs.ecdh(EccCurve.P256, date), true)
        SubkeyType.ENCRYPT_ECDH_P384 -> Generated(BcEcKeyPairs.ecdh(EccCurve.P384, date), true)
        SubkeyType.ENCRYPT_ECDH_P521 -> Generated(BcEcKeyPairs.ecdh(EccCurve.P521, date), true)
        SubkeyType.SIGN_ECDSA_P256 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P256, date), true)
        SubkeyType.SIGN_ECDSA_P384 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P384, date), true)
        SubkeyType.SIGN_ECDSA_P521 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P521, date), true)
        SubkeyType.SIGN_ED25519 -> BcKeyPairs.ed25519(date).let { Generated(it.pair, true) }
        SubkeyType.SIGN_ED448 -> BcKeyPairs.ed448(date).let { Generated(it.pair, true) }
        SubkeyType.ENCRYPT_ELGAMAL -> Generated(
            JcaPlatform.elGamalKeyPair(PgpAlgorithmPolicy.defaultElGamalBits, date),
            false,
        )
        SubkeyType.AUTH_RSA -> Generated(JcaPlatform.rsaSignMasterPair(rsaBits, date), false)
        SubkeyType.AUTH_ED25519 -> BcKeyPairs.ed25519(date).let { Generated(it.pair, true) }
        SubkeyType.AUTH_ED448 -> BcKeyPairs.ed448(date).let { Generated(it.pair, true) }
        SubkeyType.AUTH_ECDSA_P256 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P256, date), true)
        SubkeyType.AUTH_ECDSA_P384 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P384, date), true)
        SubkeyType.AUTH_ECDSA_P521 -> Generated(BcEcKeyPairs.ecdsa(EccCurve.P521, date), true)
    }

    /**
     * Returns whether the given OpenPGP algorithm tag requires BC lightweight operators.
     *
     * Covers ECDH, ECDSA, EdDSA, Ed25519, Ed448, X25519, and X448.
     */
    fun useBcLightweight(algorithm: Int): Boolean = algorithm in BC_ALGORITHMS

    private val BC_ALGORITHMS = setOf(
        PGPPublicKey.ECDH,
        PGPPublicKey.ECDSA,
        PGPPublicKey.EC,
        PublicKeyAlgorithmTags.EDDSA,
        PublicKeyAlgorithmTags.EDDSA_LEGACY,
        PublicKeyAlgorithmTags.Ed25519,
        PublicKeyAlgorithmTags.Ed448,
        PublicKeyAlgorithmTags.X25519,
        PublicKeyAlgorithmTags.X448,
    )
}

/**
 * Subkey kinds that can be added to an existing secret key ring.
 *
 * Each variant maps to a specific algorithm and intended capability (encrypt, sign, or authenticate).
 */
enum class SubkeyType {
    ENCRYPT_RSA,
    SIGN_RSA,
    ENCRYPT_CV25519,
    ENCRYPT_X448,
    ENCRYPT_ECDH_P256,
    ENCRYPT_ECDH_P384,
    ENCRYPT_ECDH_P521,
    SIGN_ECDSA_P256,
    SIGN_ECDSA_P384,
    SIGN_ECDSA_P521,
    SIGN_ED25519,
    SIGN_ED448,
    ENCRYPT_ELGAMAL,
    AUTH_RSA,
    AUTH_ED25519,
    AUTH_ED448,
    AUTH_ECDSA_P256,
    AUTH_ECDSA_P384,
    AUTH_ECDSA_P521,
}
