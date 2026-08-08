package ltechnologies.onionphone.pgpshield.engine

import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Coverage for AEAD/SEIPDv2, compression, PBE, one-pass sign+encrypt, and v6 keys.
 */
class BcModernOpenPgpSurfaceTest {
    @Test
    fun v4_keygen_usesArgon2AeadSecretProtect() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "argon2-v4-pass".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest("Argon2V4 <a2@e.com>", pass, KeyAlgorithmType.ED25519),
        )
        assertTrue(
            PgpRecipientCapabilities.preferAeadSecretProtect(key.secretArmored),
            "new v4 secrets must use Argon2+AEAD protection",
        )
        val plain = "argon2 v4 unlock".toByteArray()
        val enc = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = plain,
                recipientKeyRings = listOf(key.publicArmored),
                integrity = MessageIntegrity.MDC,
            ),
        )
        val dec = PgpDecryptor().decrypt(
            DecryptRequest(enc.ciphertext, key.secretArmored, pass.copyOf()),
        )
        assertArrayEquals(plain, dec.plaintext)
    }

    @Test
    fun aeadSeipdV2_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "aead-pass".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest("Aead <a@e.com>", pass, KeyAlgorithmType.ED25519),
        )
        val plain = "hello aead seipdv2".toByteArray()
        val enc = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = plain,
                recipientKeyRings = listOf(key.publicArmored),
                integrity = MessageIntegrity.SEIPD_V2_AEAD,
                asciiArmor = true,
            ),
        )
        val dec = PgpDecryptor().decrypt(
            DecryptRequest(enc.ciphertext, key.secretArmored, pass.copyOf()),
        )
        assertArrayEquals(plain, dec.plaintext)
        assertTrue(dec.verified)
    }

    @Test
    fun mdc_withZlibCompression_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "zlib-pass".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest("Zlib <z@e.com>", pass, KeyAlgorithmType.ED25519),
        )
        val plain = ("compress-me\n").repeat(200).toByteArray()
        val enc = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = plain,
                recipientKeyRings = listOf(key.publicArmored),
                integrity = MessageIntegrity.MDC,
                compression = MessageCompression.ZLIB,
            ),
        )
        val dec = PgpDecryptor().decrypt(
            DecryptRequest(enc.ciphertext, key.secretArmored, pass.copyOf()),
        )
        assertArrayEquals(plain, dec.plaintext)
    }

    @Test
    fun pbeArgon2_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val msgPass = "pbe-message-pass".toCharArray()
        val plain = "passphrase-only message".toByteArray()
        val enc = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = plain,
                recipientKeyRings = emptyList(),
                passphrase = msgPass,
                integrity = MessageIntegrity.MDC,
            ),
        )
        val dec = PgpDecryptor().decrypt(
            DecryptRequest(
                ciphertext = enc.ciphertext,
                secretKeyRingArmored = null,
                passphrase = msgPass.copyOf(),
            ),
        )
        assertArrayEquals(plain, dec.plaintext)
    }

    @Test
    fun signAndEncrypt_onePass_verifies() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "ops-pass".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest("Ops <o@e.com>", pass, KeyAlgorithmType.ED25519),
        )
        val plain = "signed and encrypted".toByteArray()
        val enc = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = plain,
                recipientKeyRings = listOf(key.publicArmored),
                integrity = MessageIntegrity.MDC,
                signSecretRingArmored = key.secretArmored,
                signPassphrase = pass.copyOf(),
            ),
        )
        val dec = PgpDecryptor().decrypt(
            DecryptRequest(
                ciphertext = enc.ciphertext,
                secretKeyRingArmored = key.secretArmored,
                passphrase = pass.copyOf(),
                signerPublicKeyRingsArmored = listOf(key.publicArmored),
            ),
        )
        assertArrayEquals(plain, dec.plaintext)
        assertEquals(true, dec.signatureValid)
        assertNotNull(dec.signerKeyId)
    }

    @Test
    fun v6_ed25519_usesNativeTags() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "v6-pass".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest(
                userId = "V6 <v6@e.com>",
                passphrase = pass,
                algorithmType = KeyAlgorithmType.ED25519,
                keyFormat = KeyFormat.V6,
            ),
        )
        val ring = PGPUtil.getDecoderStream(key.secretArmored.inputStream()).use { input ->
            PGPObjectFactory(input, JcaKeyFingerprintCalculator()).nextObject() as PGPSecretKeyRing
        }
        val algos = ring.secretKeys.asSequence().map { it.publicKey.algorithm }.toSet()
        assertTrue(
            PublicKeyAlgorithmTags.Ed25519 in algos || PublicKeyAlgorithmTags.X25519 in algos,
            "expected native Ed25519/X25519 tags, got $algos",
        )
        val plain = "v6 roundtrip".toByteArray()
        val enc = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = plain,
                recipientKeyRings = listOf(key.publicArmored),
                integrity = MessageIntegrity.MDC,
            ),
        )
        val dec = PgpDecryptor().decrypt(
            DecryptRequest(enc.ciphertext, key.secretArmored, pass.copyOf()),
        )
        assertArrayEquals(plain, dec.plaintext)
    }

    @Test
    fun librePgpV5Aead_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "v5-aead-pass".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest("V5Aead <v5@e.com>", pass, KeyAlgorithmType.ED25519),
        )
        val plain = "hello librepgp v5 aead".toByteArray()
        val enc = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = plain,
                recipientKeyRings = listOf(key.publicArmored),
                integrity = MessageIntegrity.LIBREPGP_V5_AEAD,
                forceIntegrity = true,
                asciiArmor = true,
            ),
        )
        val dec = PgpDecryptor().decrypt(
            DecryptRequest(enc.ciphertext, key.secretArmored, pass.copyOf()),
        )
        assertArrayEquals(plain, dec.plaintext)
        assertTrue(dec.verified)
    }

    @Test
    fun v6_ed25519_aeadEncrypt_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "v6-aead-pass".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest(
                userId = "V6Aead <v6a@e.com>",
                passphrase = pass,
                algorithmType = KeyAlgorithmType.ED25519,
                keyFormat = KeyFormat.V6,
            ),
        )
        val plain = "v6 aead roundtrip".toByteArray()
        val enc = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = plain,
                recipientKeyRings = listOf(key.publicArmored),
                integrity = MessageIntegrity.SEIPD_V2_AEAD,
                forceIntegrity = true,
            ),
        )
        val dec = PgpDecryptor().decrypt(
            DecryptRequest(enc.ciphertext, key.secretArmored, pass.copyOf()),
        )
        assertArrayEquals(plain, dec.plaintext)
        assertTrue(dec.verified)
    }

    @Test
    fun v6_passphraseChange_keepsAeadProtect() {
        BouncyCastleProviderHolder.ensureRegistered()
        val oldPass = "old-v6-pass".toCharArray()
        val newPass = "new-v6-pass".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest(
                userId = "V6Pass <vp@e.com>",
                passphrase = oldPass,
                algorithmType = KeyAlgorithmType.ED25519,
                keyFormat = KeyFormat.V6,
            ),
        )
        assertTrue(PgpRecipientCapabilities.preferAeadSecretProtect(key.secretArmored))
        val rewrapped = KeyPassphraseChanger().changePassphrase(
            ChangePassphraseRequest(
                secretKeyRingArmored = key.secretArmored,
                oldPassphrase = oldPass.copyOf(),
                newPassphrase = newPass,
                aeadProtect = true,
            ),
        )
        val plain = "after rewrap".toByteArray()
        val enc = PgpEncryptor().encrypt(
            EncryptRequest(
                plaintext = plain,
                recipientKeyRings = listOf(key.publicArmored),
                integrity = MessageIntegrity.MDC,
            ),
        )
        val dec = PgpDecryptor().decrypt(
            DecryptRequest(enc.ciphertext, rewrapped, newPass.copyOf()),
        )
        assertArrayEquals(plain, dec.plaintext)
    }

    @Test
    fun v4_nativeCurveTags_whenRequested() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "native-pass".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest(
                userId = "Native <n@e.com>",
                passphrase = pass,
                algorithmType = KeyAlgorithmType.ED25519,
                preferNativeCurveTags = true,
            ),
        )
        val ring = PGPUtil.getDecoderStream(key.secretArmored.inputStream()).use { input ->
            PGPObjectFactory(input, JcaKeyFingerprintCalculator()).nextObject() as PGPSecretKeyRing
        }
        val algos = ring.secretKeys.asSequence().map { it.publicKey.algorithm }.toSet()
        assertTrue(
            PublicKeyAlgorithmTags.Ed25519 in algos || PublicKeyAlgorithmTags.X25519 in algos,
            "expected native tags, got $algos",
        )
    }

    @Test
    fun subkeyRevocationCert_generates() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "rev-pass".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest("Rev <r@e.com>", pass, KeyAlgorithmType.ED25519),
        )
        val ring = PGPUtil.getDecoderStream(key.secretArmored.inputStream()).use { input ->
            PGPObjectFactory(input, JcaKeyFingerprintCalculator()).nextObject() as PGPSecretKeyRing
        }
        val subId = ring.secretKeys.asSequence().drop(1).first().keyID
        val cert = RevocationCertGenerator().generate(
            RevocationCertRequest(
                secretKeyRingArmored = key.secretArmored,
                passphrase = pass.copyOf(),
                subkeyId = subId,
            ),
        )
        assertTrue(cert.isNotEmpty())
        assertTrue(String(cert).contains("BEGIN PGP SIGNATURE") || String(cert).contains("BEGIN PGP PUBLIC KEY"))
    }
}
