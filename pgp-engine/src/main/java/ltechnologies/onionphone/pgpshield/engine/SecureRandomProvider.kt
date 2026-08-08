package ltechnologies.onionphone.pgpshield.engine

/**
 * Centralized cryptographically strong random number generation.
 *
 * Prefers a **non-blocking** CSPRNG suitable for Android key generation.
 * [SecureRandom.getInstanceStrong] maps to `NativePRNGBlocking` on Android/OpenJDK
 * and can stall RSA/ECC keygen for seconds when the entropy pool is drained —
 * that looks like a hung UI, not cryptography.
 */

import java.security.SecureRandom

/** Shared secure random source for key generation and IV/salt creation. */
object SecureRandomProvider {
    /**
     * Process-wide CSPRNG. Thread-safe; do not replace with [SecureRandom.getInstanceStrong].
     */
    val secureRandom: SecureRandom = createNonBlocking()

    private fun createNonBlocking(): SecureRandom {
        // Order: Android/OpenJDK non-blocking urandom → NIST DRBG → platform default.
        for (algorithm in listOf("NativePRNGNonBlocking", "DRBG")) {
            try {
                return SecureRandom.getInstance(algorithm)
            } catch (_: Exception) {
                // try next
            }
        }
        return SecureRandom()
    }
}
