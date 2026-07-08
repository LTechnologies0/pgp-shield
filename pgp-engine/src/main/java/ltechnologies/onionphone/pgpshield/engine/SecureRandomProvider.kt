package ltechnologies.onionphone.pgpshield.engine

/**
 * Centralized cryptographically strong random number generation.
 *
 * Exposes a single [SecureRandom] instance backed by the platform's strongest
 * available provider (`getInstanceStrong()`).
 */

import java.security.SecureRandom

/** Shared secure random source for key generation and IV/salt creation. */
object SecureRandomProvider {
    /** Platform strong `SecureRandom` instance used throughout the engine. */
    val secureRandom: SecureRandom = SecureRandom.getInstanceStrong()
}
