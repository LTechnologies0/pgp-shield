package ltechnologies.onionphone.pgpshield.engine

/**
 * Bouncy Castle lightweight key generation for modern OpenPGP curves.
 *
 * Generates Ed25519, Ed448, X25519, and X448 key pairs via the BC crypto API
 * (not JCA), wrapped as `BcPGPKeyPair` for use with BC lightweight operators.
 */

import java.util.Date
import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator
import org.bouncycastle.crypto.generators.Ed448KeyPairGenerator
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator
import org.bouncycastle.crypto.generators.X448KeyPairGenerator
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters
import org.bouncycastle.crypto.params.Ed448KeyGenerationParameters
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters
import org.bouncycastle.crypto.params.X448KeyGenerationParameters
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPKeyPair
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair

/** BC lightweight generators for Curve25519 and Ed448 family keys. */
object BcKeyPairs {
    /**
     * Generated key pair; [useBcLightweight] is always `true` for this backend.
     *
     * @property pair `BcPGPKeyPair` ready for ring construction.
     * @property useBcLightweight Always `true` — must use BC operators.
     */
    data class Result(val pair: PGPKeyPair, val useBcLightweight: Boolean = true)

    /** Ed25519 signing key pair (`EDDSA` / legacy Ed25519 tag). */
    fun ed25519(date: Date): Result =
        Result(BcPGPKeyPair(PGPPublicKey.EDDSA, ed25519Raw(), date))

    /** X25519 (Cv25519) ECDH encryption subkey pair. */
    fun x25519(date: Date): Result =
        Result(BcPGPKeyPair(PGPPublicKey.ECDH, x25519Raw(), date))

    /** Ed448 signing key pair. */
    fun ed448(date: Date): Result =
        Result(BcPGPKeyPair(PublicKeyAlgorithmTags.Ed448, ed448Raw(), date))

    /** X448 ECDH encryption subkey pair. */
    fun x448(date: Date): Result =
        Result(BcPGPKeyPair(PublicKeyAlgorithmTags.X448, x448Raw(), date))

    private fun ed25519Raw(): AsymmetricCipherKeyPair {
        val gen = Ed25519KeyPairGenerator()
        gen.init(Ed25519KeyGenerationParameters(SecureRandomProvider.secureRandom))
        return gen.generateKeyPair()
    }

    private fun x25519Raw(): AsymmetricCipherKeyPair {
        val gen = X25519KeyPairGenerator()
        gen.init(X25519KeyGenerationParameters(SecureRandomProvider.secureRandom))
        return gen.generateKeyPair()
    }

    private fun ed448Raw(): AsymmetricCipherKeyPair {
        val gen = Ed448KeyPairGenerator()
        gen.init(Ed448KeyGenerationParameters(SecureRandomProvider.secureRandom))
        return gen.generateKeyPair()
    }

    private fun x448Raw(): AsymmetricCipherKeyPair {
        val gen = X448KeyPairGenerator()
        gen.init(X448KeyGenerationParameters(SecureRandomProvider.secureRandom))
        return gen.generateKeyPair()
    }
}
