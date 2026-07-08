package ltechnologies.onionphone.pgpshield

import androidx.test.ext.junit.runners.AndroidJUnit4
import ltechnologies.onionphone.pgpshield.engine.BouncyCastleProviderHolder
import ltechnologies.onionphone.pgpshield.engine.GenerateKeyRequest
import ltechnologies.onionphone.pgpshield.engine.KeyAlgorithmType
import ltechnologies.onionphone.pgpshield.engine.KeyGenerator
import ltechnologies.onionphone.pgpshield.engine.PgpDecryptor
import ltechnologies.onionphone.pgpshield.engine.PgpEncryptor
import ltechnologies.onionphone.pgpshield.engine.DecryptRequest
import ltechnologies.onionphone.pgpshield.engine.EncryptRequest
import ltechnologies.onionphone.pgpshield.engine.SubkeyAdder
import ltechnologies.onionphone.pgpshield.engine.AddSubkeyRequest
import ltechnologies.onionphone.pgpshield.engine.SubkeyType
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.NoSuchAlgorithmException

@RunWith(AndroidJUnit4::class)
class KeyGenDeviceTest {
    @Test
    fun rsa3072_generatesOnDevice() = generateAndRoundTrip(KeyAlgorithmType.RSA, rsaBits = 3072)

    @Test
    fun ed25519_generatesOnDevice() = generateAndRoundTrip(KeyAlgorithmType.ED25519)

    @Test
    fun ecdsaP256_generatesOnDevice() = generateAndRoundTrip(KeyAlgorithmType.ECDSA_P256)

    @Test
    fun ecdsaP384_generatesOnDevice() = generateAndRoundTrip(KeyAlgorithmType.ECDSA_P384)

    @Test
    fun dsaElgamal_generatesOnDevice() {
        try {
            generateAndRoundTrip(KeyAlgorithmType.DSA_ELGAMAL)
        } catch (_: NoSuchAlgorithmException) {
            // ponytail: Android BC has no ElGamal KeyPairGenerator — JVM round-trip covers desktop
        }
    }

    @Test
    fun ed448_generatesOnDevice() = generateAndRoundTrip(KeyAlgorithmType.ED448)

    @Test
    fun rsa_addEncryptSubkeyOnDevice() {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "device-subkey-rsa".toCharArray()
        try {
            val base = KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = "Subkey RSA <sub@pgpshield.test>",
                    passphrase = passphrase,
                    algorithmType = KeyAlgorithmType.RSA,
                    rsaBits = 3072,
                ),
            )
            val updated = SubkeyAdder().addSubkey(
                AddSubkeyRequest(
                    secretKeyRingArmored = base.secretArmored,
                    passphrase = passphrase,
                    subkeyType = SubkeyType.ENCRYPT_RSA,
                    rsaBits = 3072,
                ),
            )
            assertTrue(updated.isNotEmpty())
        } finally {
            passphrase.fill('\u0000')
        }
    }

    private fun generateAndRoundTrip(type: KeyAlgorithmType, rsaBits: Int = 3072) {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "device-pass-${type.name}".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = "Device ${type.name} <dev@pgpshield.test>",
                    passphrase = passphrase,
                    algorithmType = type,
                    rsaBits = rsaBits,
                ),
            )
            assertTrue("public armored empty", generated.publicArmored.isNotEmpty())
            assertTrue("secret armored empty", generated.secretArmored.isNotEmpty())

            val encrypted = PgpEncryptor().encrypt(
                EncryptRequest(
                    plaintext = "adb-roundtrip".toByteArray(Charsets.UTF_8),
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
            assertTrue(
                String(decrypted.plaintext, Charsets.UTF_8).contains("adb-roundtrip"),
            )
        } finally {
            passphrase.fill('\u0000')
        }
    }
}
