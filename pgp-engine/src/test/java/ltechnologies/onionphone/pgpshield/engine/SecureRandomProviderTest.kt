package ltechnologies.onionphone.pgpshield.engine

import java.security.SecureRandom
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class SecureRandomProviderTest {
    @Test
    fun prefersNonBlockingAlgorithm() {
        val rng = SecureRandomProvider.secureRandom
        // getInstanceStrong() → NativePRNGBlocking on OpenJDK/Android; we must not use that.
        assertFalse(
            rng.algorithm.contains("Blocking", ignoreCase = true) &&
                !rng.algorithm.contains("NonBlocking", ignoreCase = true),
            "Unexpected blocking SecureRandom: ${rng.provider}/${rng.algorithm}",
        )
        val buf = ByteArray(32)
        rng.nextBytes(buf)
        assertTrue(buf.any { it != 0.toByte() })
    }

    @Test
    fun isUsableAsKeygenEntropy() {
        val kpg = java.security.KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048, SecureRandomProvider.secureRandom)
        val pair = kpg.generateKeyPair()
        assertTrue(pair.private.encoded.isNotEmpty())
    }
}
