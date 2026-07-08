package ltechnologies.onionphone.pgpshield.engine

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test

class PgpFileCryptoTest {
    companion object {
        private lateinit var generated: GeneratedKeyRing
        private val passphrase = "file-crypto-test-pass".toCharArray()

        @BeforeAll
        @JvmStatic
        fun generateKey() {
            BouncyCastleProviderHolder.ensureRegistered()
            generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = "File Crypto <file@example.com>",
                    passphrase = passphrase,
                    algorithmType = KeyAlgorithmType.RSA,
                    rsaBits = 2048,
                ),
            )
        }
    }

    @Test
    fun binaryFileEncryptDecrypt_roundTrip() {
        val fileBytes = byteArrayOf(0x00, 0x01, 0x02, 0xFF.toByte(), 0x7F, 0x48, 0x69)
        val encrypted = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = fileBytes,
                recipientKeyRings = listOf(generated.publicArmored),
                asciiArmor = false,
                fileName = "photo.bin",
            ),
        )
        val decrypted = PgpDecryptor().decrypt(
            DecryptRequest(
                ciphertext = encrypted.ciphertext,
                secretKeyRingArmored = generated.secretArmored,
                passphrase = passphrase,
            ),
        )
        assertArrayEquals(fileBytes, decrypted.plaintext)
        assertEquals("photo.bin", decrypted.fileName)
    }

    @Test
    fun armoredFileEncryptDecrypt_roundTrip() {
        val fileBytes = "plain file content\n".toByteArray(Charsets.UTF_8)
        val encrypted = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = fileBytes,
                recipientKeyRings = listOf(generated.publicArmored),
                asciiArmor = true,
                fileName = "notes.txt",
            ),
        )
        assertTrue(String(encrypted.ciphertext, Charsets.UTF_8).contains("BEGIN PGP MESSAGE"))
        val decrypted = PgpDecryptor().decrypt(
            DecryptRequest(
                ciphertext = encrypted.ciphertext,
                secretKeyRingArmored = generated.secretArmored,
                passphrase = passphrase,
            ),
        )
        assertArrayEquals(fileBytes, decrypted.plaintext)
        assertEquals("notes.txt", decrypted.fileName)
    }

    @Test
    fun detachedBinarySignVerify_roundTrip() {
        val fileBytes = byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte())
        val signed = PgpSigner().sign(
            SignRequest(
                data = fileBytes,
                secretKeyRingArmored = generated.secretArmored,
                passphrase = passphrase,
                detachedBinary = true,
            ),
        )
        assertTrue(String(signed.output, Charsets.UTF_8).contains("BEGIN PGP SIGNATURE"))
        val result = PgpVerifier().verify(
            VerifyRequest(
                signedOrDetached = signed.output,
                detachedMessage = fileBytes,
                publicKeyRingsArmored = listOf(generated.publicArmored),
                binaryDocument = true,
            ),
        )
        assertTrue(result.valid, result.error)
        assertEquals(generated.masterKeyId, result.signerKeyId)
        assertArrayEquals(fileBytes, result.message)
    }

    @Test
    fun wrongPassphrase_decryptFails() {
        val encrypted = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = "secret".toByteArray(Charsets.UTF_8),
                recipientKeyRings = listOf(generated.publicArmored),
                asciiArmor = false,
            ),
        )
        assertThrows(Exception::class.java) {
            PgpDecryptor().decrypt(
                DecryptRequest(
                    ciphertext = encrypted.ciphertext,
                    secretKeyRingArmored = generated.secretArmored,
                    passphrase = "wrong-pass".toCharArray(),
                ),
            )
        }
    }
}
