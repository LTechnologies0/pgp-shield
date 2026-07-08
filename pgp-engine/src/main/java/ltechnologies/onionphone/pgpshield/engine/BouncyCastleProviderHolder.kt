package ltechnologies.onionphone.pgpshield.engine

/**
 * Bouncy Castle JCA provider registration.
 *
 * Ensures the BC security provider is installed before any cryptographic operation
 * that depends on BC algorithms (DSA, ElGamal, Ed25519, etc.).
 */

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.Security

/** Lazily registers the Bouncy Castle JCA provider on first access. */
object BouncyCastleProviderHolder {
    /** Registered BC provider name (`BC`). */
    const val PROVIDER: String = BouncyCastleProvider.PROVIDER_NAME

    init {
        if (Security.getProvider(PROVIDER) == null) {
            Security.addProvider(BouncyCastleProvider())
        }
    }

    /** Idempotent: triggers static init so the BC provider is registered. */
    fun ensureRegistered() {
        // triggers init
    }
}
