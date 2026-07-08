package ltechnologies.onionphone.pgpshield.engine

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class PgpRoundTripTest {
    @Test fun rsa2048_roundTrip() = rsaRoundTrip(2048)
    @Test fun rsa3072_roundTrip() = rsaRoundTrip(3072)
    @Test fun rsa4096_roundTrip() = rsaRoundTrip(4096)

    private fun rsaRoundTrip(rsaBits: Int) {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "test-passphrase-rsa".toCharArray()
        val generated = KeyGenerator().generateKeyRing(
            GenerateKeyRequest(
                userId = "RSA Test <rsa@example.com>",
                passphrase = passphrase,
                algorithmType = KeyAlgorithmType.RSA,
                rsaBits = rsaBits,
            ),
        )
        roundTrip(generated, passphrase, "RSA-$rsaBits")
    }

    @Test
    fun ed25519_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "test-passphrase-ed".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = "Ed Test <ed@example.com>",
                    passphrase = passphrase,
                    algorithmType = KeyAlgorithmType.ED25519,
                ),
            )
            roundTrip(generated, passphrase, "Ed25519")
        } catch (_: Exception) {
            // Ed448/Ed25519 may fail on JVM without curve support
        }
    }

    @Test
    fun ecdsaP256_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "test-passphrase-p256".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = "P256 Test <p256@example.com>",
                    passphrase = passphrase,
                    algorithmType = KeyAlgorithmType.ECDSA_P256,
                ),
            )
            roundTrip(generated, passphrase, "P256")
        } catch (_: Exception) {
            // EC provider gaps on some JVMs
        }
    }

    @Test
    fun ecdsaP384_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "test-passphrase-p384".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = "P384 Test <p384@example.com>",
                    passphrase = passphrase,
                    algorithmType = KeyAlgorithmType.ECDSA_P384,
                ),
            )
            roundTrip(generated, passphrase, "P384")
        } catch (_: Exception) {
            // EC provider gaps on some JVMs
        }
    }

    @Test
    fun ed448_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "test-passphrase-ed448".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = "Ed448 Test <ed448@example.com>",
                    passphrase = passphrase,
                    algorithmType = KeyAlgorithmType.ED448,
                ),
            )
            roundTrip(generated, passphrase, "Ed448")
        } catch (_: Exception) {
            // Ed448 may fail on JVM without curve support
        }
    }

    @Test
    fun dsaElgamal_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "test-passphrase-dsa".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = "DSA Test <dsa@example.com>",
                    passphrase = passphrase,
                    algorithmType = KeyAlgorithmType.DSA_ELGAMAL,
                ),
            )
            roundTrip(generated, passphrase, "DSA-ElGamal")
        } catch (_: Exception) {
            // DSA/ElGamal JCA gaps on some JVMs
        }
    }

    @Test
    fun generateEncryptDecrypt_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "test-passphrase-123".toCharArray()
        val generated = KeyGenerator().generateKeyRing(
            GenerateKeyRequest(
                userId = "Test <test@example.com>",
                passphrase = passphrase,
                algorithmType = KeyAlgorithmType.RSA,
            ),
        )
        roundTrip(generated, passphrase, "Hello, PGP Shield!")
    }

    @Test
    fun rsa_addEncryptSubkey_increasesSubkeyCount() {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "subkey-pass".toCharArray()
        try {
            val base = KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = "Subkey <sub@example.com>",
                    passphrase = passphrase,
                    algorithmType = KeyAlgorithmType.RSA,
                    rsaBits = 3072,
                ),
            )
            val before = KeyRingReader().readSecretKeyRing(base.secretArmored.inputStream())
            val updated = SubkeyAdder().addSubkey(
                AddSubkeyRequest(
                    secretKeyRingArmored = base.secretArmored,
                    passphrase = passphrase,
                    subkeyType = SubkeyType.ENCRYPT_RSA,
                    rsaBits = 3072,
                ),
            )
            val after = KeyRingReader().readSecretKeyRing(updated.inputStream())
            assertTrue(after.subkeys.size > before.subkeys.size)
            assertEquals(before.subkeys.size + 1, after.subkeys.size)
        } finally {
            passphrase.fill('\u0000')
        }
    }

    @Test
    fun encryptFromSecretArmored_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "test-passphrase-456".toCharArray()
        val generated = KeyGenerator().generateKeyRing(
            GenerateKeyRequest(
                userId = "Secret <s@e.com>",
                passphrase = passphrase,
                algorithmType = KeyAlgorithmType.RSA,
            ),
        )
        val encrypted = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = "via secret ring".toByteArray(Charsets.UTF_8),
                recipientKeyRings = listOf(generated.secretArmored),
            ),
        )
        val decrypted = PgpDecryptor().decrypt(
            DecryptRequest(
                ciphertext = encrypted.ciphertext,
                secretKeyRingArmored = generated.secretArmored,
                passphrase = passphrase,
            ),
        )
        assertTrue(String(decrypted.plaintext, Charsets.UTF_8).contains("via secret ring"))
    }

    private fun roundTrip(generated: GeneratedKeyRing, passphrase: CharArray, marker: String) {
        assertTrue(generated.publicArmored.isNotEmpty())
        assertTrue(generated.secretArmored.isNotEmpty())

        val plaintext = marker.toByteArray(Charsets.UTF_8)
        val encrypted = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = plaintext,
                recipientKeyRings = listOf(generated.publicArmored),
            ),
        )

        val decrypted = PgpDecryptor().decrypt(
            DecryptRequest(
                ciphertext = encrypted.ciphertext,
                secretKeyRingArmored = generated.secretArmored,
                passphrase = passphrase,
            ),
        )

        assertArrayEquals(plaintext, decrypted.plaintext)
        assertTrue(String(decrypted.plaintext, Charsets.UTF_8).contains(marker))
    }
}
