package ltechnologies.onionphone.pgpshield.engine

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class BcParallelEncryptTest {
    @Test
    fun encryptMany_reusesRecipients_roundTrip() = runBlocking {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "parallel-pass".toCharArray()
        val key = KeyGenerator().generateKeyRing(
            GenerateKeyRequest("Par <p@e.com>", pass, KeyAlgorithmType.ED25519),
        )
        val plaintexts = listOf(
            EncryptPlaintext("one".toByteArray(), "a.txt"),
            EncryptPlaintext("two".toByteArray(), "b.txt"),
            EncryptPlaintext("three".toByteArray(), "c.txt"),
        )
        val results = PgpEncryptor().encryptMany(plaintexts, listOf(key.publicArmored), parallelism = 3)
        assertEquals(3, results.size)
        results.zip(plaintexts).forEach { (enc, pt) ->
            val dec = PgpDecryptor().decrypt(
                DecryptRequest(enc.ciphertext, key.secretArmored, pass.copyOf()),
            )
            assertArrayEquals(pt.plaintext, dec.plaintext)
            assertTrue(dec.verified)
        }
    }
}
