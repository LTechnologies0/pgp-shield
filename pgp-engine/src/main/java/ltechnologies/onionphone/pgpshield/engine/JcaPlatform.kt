package ltechnologies.onionphone.pgpshield.engine

/**
 * JCA platform integration for OpenPGP key generation on Android.
 *
 * Selects AndroidOpenSSL, Conscrypt, or BC JCA providers for RSA/EC key generation
 * while routing DSA/ElGamal through Bouncy Castle. Also exposes BC digest calculators
 * for OpenPGP checksums.
 */

import java.security.KeyPairGenerator
import java.security.Security
import java.security.spec.ECGenParameterSpec
import java.util.Date
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair

/**
 * Android-aware JCA key generation and digest providers for OpenPGP.
 *
 * Android blocks BC JCA for some algorithms; this object picks a working provider per algorithm.
 */
object JcaPlatform {
    /** BC lightweight digest calculator provider for OpenPGP packet checksums. */
    val digestCalculators: BcPGPDigestCalculatorProvider = BcPGPDigestCalculatorProvider()

    private val preferredProviders = listOf("AndroidOpenSSL", "Conscrypt", "BC")
    private val bcOnlyAlgorithms = setOf("DSA", "ElGamal", "DH")

    /**
     * Returns a [KeyPairGenerator] for [algorithm], preferring platform providers.
     *
     * DSA, ElGamal, and DH always use the BC JCA provider.
     */
    fun keyPairGenerator(algorithm: String): KeyPairGenerator {
        if (algorithm in bcOnlyAlgorithms) {
            return KeyPairGenerator.getInstance(algorithm, BouncyCastleProviderHolder.PROVIDER)
        }
        for (name in preferredProviders) {
            if (Security.getProvider(name) == null) continue
            try {
                return KeyPairGenerator.getInstance(algorithm, name)
            } catch (_: Exception) {
                // next
            }
        }
        for (provider in Security.getProviders()) {
            if (provider.name.contains("KeyStore", ignoreCase = true)) continue
            try {
                return KeyPairGenerator.getInstance(algorithm, provider.name)
            } catch (_: Exception) {
                // next
            }
        }
        return KeyPairGenerator.getInstance(algorithm)
    }

    /** Generates an RSA key pair tagged for signing (alias for [rsaSignMasterPair]). */
    fun rsaKeyPair(bits: Int, date: Date): JcaPGPKeyPair = rsaSignMasterPair(bits, date)

    /** RSA signing master key pair (`RSA_SIGN` packet). */
    fun rsaSignMasterPair(bits: Int, date: Date): JcaPGPKeyPair {
        val kpg = keyPairGenerator("RSA")
        kpg.initialize(bits, SecureRandomProvider.secureRandom)
        return JcaPGPKeyPair(PGPPublicKey.RSA_SIGN, kpg.generateKeyPair(), date)
    }

    /** RSA encryption subkey pair (`RSA_ENCRYPT` packet). */
    fun rsaEncryptSubPair(bits: Int, date: Date): JcaPGPKeyPair {
        val kpg = keyPairGenerator("RSA")
        kpg.initialize(bits, SecureRandomProvider.secureRandom)
        return JcaPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, kpg.generateKeyPair(), date)
    }

    /** DSA primary key pair for legacy DSA/ElGamal layouts. */
    fun dsaKeyPair(bits: Int, date: Date): JcaPGPKeyPair {
        val kpg = keyPairGenerator("DSA")
        kpg.initialize(bits, SecureRandomProvider.secureRandom)
        return JcaPGPKeyPair(PGPPublicKey.DSA, kpg.generateKeyPair(), date)
    }

    /** ElGamal encryption subkey pair for legacy DSA/ElGamal layouts. */
    fun elGamalKeyPair(bits: Int, date: Date): JcaPGPKeyPair {
        val kpg = keyPairGenerator("ElGamal")
        kpg.initialize(bits, SecureRandomProvider.secureRandom)
        return JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, kpg.generateKeyPair(), date)
    }

    /**
     * NIST elliptic-curve key pair for ECDSA or ECDH OpenPGP packets.
     *
     * Tries platform EC/ECDSA/ECDH generators before falling back to BC.
     */
    fun ecKeyPair(curve: EccCurve, pgpAlgorithm: Int, date: Date): JcaPGPKeyPair {
        val spec = ECGenParameterSpec(curve.jcaName)
        val jcaNames = when (pgpAlgorithm) {
            PGPPublicKey.ECDSA -> listOf("EC", "ECDSA")
            PGPPublicKey.ECDH -> listOf("EC", "ECDH")
            else -> listOf("EC")
        }
        for (name in jcaNames) {
            try {
                val kpg = keyPairGenerator(name)
                kpg.initialize(spec, SecureRandomProvider.secureRandom)
                return JcaPGPKeyPair(pgpAlgorithm, kpg.generateKeyPair(), date)
            } catch (_: Exception) {
                // next
            }
        }
        val kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProviderHolder.PROVIDER)
        kpg.initialize(spec, SecureRandomProvider.secureRandom)
        return JcaPGPKeyPair(pgpAlgorithm, kpg.generateKeyPair(), date)
    }
}

/**
 * NIST elliptic curves supported for JCA and BC lightweight key generation.
 *
 * @property jcaName Name passed to `ECGenParameterSpec`.
 * @property nistName NIST curve identifier for BC lightweight generation.
 */
enum class EccCurve(val jcaName: String, val nistName: String) {
    P256("P-256", "P-256"),
    P384("P-384", "P-384"),
    P521("P-521", "P-521"),
}
