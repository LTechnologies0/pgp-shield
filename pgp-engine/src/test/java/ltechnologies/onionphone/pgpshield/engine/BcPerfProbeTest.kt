package ltechnologies.onionphone.pgpshield.engine

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Lightweight timing probe for secret-key S2K / encrypt / decrypt paths.
 * Prints wall times; fails only on functional errors.
 */
class BcPerfProbeTest {
    @Test
    fun probe_ed25519_hot_paths() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "bench-passphrase".toCharArray()

        val t0 = System.nanoTime()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest("Bench <b@e.com>", pass, KeyAlgorithmType.ED25519),
        )
        val genMs = (System.nanoTime() - t0) / 1_000_000

        val t1 = System.nanoTime()
        val enc = PgpEncryptor().encrypt(
            EncryptRequest("hello".toByteArray(), listOf(key.publicArmored)),
        )
        val encMs = (System.nanoTime() - t1) / 1_000_000

        val t2 = System.nanoTime()
        PgpDecryptor().decrypt(DecryptRequest(enc.ciphertext, key.secretArmored, pass.copyOf()))
        val decMs = (System.nanoTime() - t2) / 1_000_000

        val t3 = System.nanoTime()
        try {
            PgpDecryptor().decrypt(DecryptRequest(enc.ciphertext, key.secretArmored, "wrong".toCharArray()))
        } catch (_: Exception) {
        }
        val wrongMs = (System.nanoTime() - t3) / 1_000_000

        println(
            "BENCH s2k=${PgpSecurityConstants.SECRET_KEY_ENCRYPTOR_S2K_COUNT} " +
                "keygen_ms=$genMs encrypt_ms=$encMs decrypt_ok_ms=$decMs decrypt_wrong_ms=$wrongMs",
        )
        assertTrue(genMs > 0 && encMs >= 0 && decMs >= 0)
    }
}
