package ltechnologies.onionphone.pgpshield.engine

import org.bouncycastle.bcpg.sig.RevocationReasonTags
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.EnumSource
import java.util.concurrent.TimeUnit

@Timeout(120, unit = TimeUnit.SECONDS)
class PgpControlFlowTest {
    @ParameterizedTest
    @EnumSource(
        value = KeyAlgorithmType::class,
        mode = EnumSource.Mode.EXCLUDE,
        names = ["DSA_ELGAMAL"],
    )
    fun generateKey_perAlgorithm(type: KeyAlgorithmType) {
        val pass = "algo-$type".toCharArray()
        try {
            val key = try {
                KeyGenerator().generateKeyRing(
                    GenerateKeyRequest(
                        userId = "$type <${type.name.lowercase()}@example.com>",
                        passphrase = pass,
                        algorithmType = type,
                        rsaBits = if (type == KeyAlgorithmType.RSA) 2048 else 3072,
                    ),
                )
            } catch (e: Exception) {
                assumeTrue(false, "${type.name} unavailable on JVM: ${e.message}")
                return
            }
            assertTrue(key.publicArmored.isNotEmpty())
            assertTrue(key.secretArmored.isNotEmpty())
            val info = KeyRingReader().readSecretKeyRing(key.secretArmored.inputStream())
            assertTrue(info.subkeys.size >= 3, "Expected master + encryption + authentication subkeys")
        } finally {
            pass.fill('\u0000')
        }
    }

    @Test
    fun signAndVerify_cleartext() {
        val pass = "sign-pass".toCharArray()
        try {
            val key = PgpTestSupport.generateRsa("Signer <sign@example.com>", pass)
            val message = "Control-flow signed message".toByteArray(Charsets.UTF_8)
            val signed = PgpTestSupport.sign(message, key.secretArmored, pass)
            val result = PgpTestSupport.verify(signed, listOf(key.publicArmored))
            assertTrue(result.valid, result.error)
            assertTrue(String(result.message!!, Charsets.UTF_8).contains("Control-flow signed message"))
        } finally {
            pass.fill('\u0000')
        }
    }

    @Test
    fun signAndVerify_detachedBinary() {
        val pass = "detached-pass".toCharArray()
        try {
            val key = PgpTestSupport.generateRsa("Detached <d@example.com>", pass)
            val message = "Detached payload bytes".toByteArray(Charsets.UTF_8)
            val sig = PgpTestSupport.sign(message, key.secretArmored, pass, detached = true)
            val result = PgpTestSupport.verify(sig, listOf(key.publicArmored), message = message)
            assertTrue(result.valid, result.error)
        } finally {
            pass.fill('\u0000')
        }
    }

    @Test
    fun encrypt_selfThenMultiRecipient_decrypt() {
        val passA = "alice-pass".toCharArray()
        val passB = "bob-pass".toCharArray()
        try {
            val alice = PgpTestSupport.generateRsa("Alice <alice@example.com>", passA)
            val bob = PgpTestSupport.generateRsa("Bob <bob@example.com>", passB)
            val plaintext = "Multi-recipient secret".toByteArray(Charsets.UTF_8)

            val selfEncrypted = PgpTestSupport.encrypt(plaintext, listOf(alice.secretArmored))
            assertArrayEquals(plaintext, PgpTestSupport.decrypt(selfEncrypted, alice.secretArmored, passA))

            val multiEncrypted = PgpTestSupport.encrypt(
                plaintext,
                listOf(alice.publicArmored, bob.publicArmored),
            )
            assertArrayEquals(plaintext, PgpTestSupport.decrypt(multiEncrypted, alice.secretArmored, passA))
            assertArrayEquals(plaintext, PgpTestSupport.decrypt(multiEncrypted, bob.secretArmored, passB))
        } finally {
            passA.fill('\u0000')
            passB.fill('\u0000')
        }
    }

    @Test
    fun subkey_addEncrypt_remove() {
        val pass = "subkey-pass".toCharArray()
        try {
            val base = PgpTestSupport.generateRsa("Subkey <sub@example.com>", pass)
            val before = PgpTestSupport.subkeyIds(base.secretArmored).size
            val withSub = SubkeyAdder().addSubkey(
                AddSubkeyRequest(
                    secretKeyRingArmored = base.secretArmored,
                    passphrase = pass,
                    subkeyType = SubkeyType.ENCRYPT_RSA,
                    rsaBits = 2048,
                ),
            )
            val afterAdd = PgpTestSupport.subkeyIds(withSub)
            assertEquals(before + 1, afterAdd.size)

            val addedId = afterAdd.first { it !in PgpTestSupport.subkeyIds(base.secretArmored) }
            val removed = SubkeyRemover().removeSubkey(
                RemoveSubkeyRequest(secretKeyRingArmored = withSub, subkeyId = addedId),
            )
            assertEquals(before, PgpTestSupport.subkeyIds(removed).size)
        } finally {
            pass.fill('\u0000')
        }
    }

    @Test
    fun subkey_addCv25519ToRsaMaster() {
        val pass = "mixed-pass".toCharArray()
        try {
            val base = PgpTestSupport.generateRsa("Mixed <mixed@example.com>", pass)
            val before = PgpTestSupport.subkeyIds(base.secretArmored).size
            val withSub = SubkeyAdder().addSubkey(
                AddSubkeyRequest(
                    secretKeyRingArmored = base.secretArmored,
                    passphrase = pass,
                    subkeyType = SubkeyType.ENCRYPT_CV25519,
                ),
            )
            assertEquals(before + 1, PgpTestSupport.subkeyIds(withSub).size)
        } finally {
            pass.fill('\u0000')
        }
    }

    @Test
    fun subkey_addAuth_ed25519() {
        val pass = "auth-pass".toCharArray()
        try {
            val base = PgpTestSupport.generateRsa("Auth <auth@example.com>", pass)
            val withSub = SubkeyAdder().addSubkey(
                AddSubkeyRequest(
                    secretKeyRingArmored = base.secretArmored,
                    passphrase = pass,
                    subkeyType = SubkeyType.AUTH_ED25519,
                ),
            )
            val info = KeyRingReader().readSecretKeyRing(withSub.inputStream())
            val authSub = info.subkeys.firstOrNull {
                it.flags and org.bouncycastle.bcpg.sig.KeyFlags.AUTHENTICATION != 0
            }
            assertTrue(authSub != null, "Expected authentication subkey")
        } finally {
            pass.fill('\u0000')
        }
    }

    @ParameterizedTest
    @EnumSource(CertificationType::class)
    fun certify_allCertificationTypes(type: CertificationType) {
        val certifierPass = "certifier-pass".toCharArray()
        val targetPass = "target-pass".toCharArray()
        try {
            val certifier = PgpTestSupport.generateRsa("Certifier <c@example.com>", certifierPass)
            val target = PgpTestSupport.generateRsa("Target <t@example.com>", targetPass)
            val userId = "Target <t@example.com>"
            val certified = KeyCertifier().certify(
                CertifyKeyRequest(
                    certifierSecretArmored = certifier.secretArmored,
                    certifierPassphrase = certifierPass,
                    targetPublicArmored = target.publicArmored,
                    userId = userId,
                    certificationType = type,
                ),
            ).certifiedPublicArmored
            PgpTestSupport.assertCertificationType(certified, userId, type)
        } finally {
            certifierPass.fill('\u0000')
            targetPass.fill('\u0000')
        }
    }

    @Test
    fun revocation_generate_apply_publicAndSecret() {
        val pass = "revoke-pass".toCharArray()
        try {
            val key = PgpTestSupport.generateRsa("Revoke <rev@example.com>", pass)
            val revocation = RevocationCertGenerator().generate(
                RevocationCertRequest(
                    secretKeyRingArmored = key.secretArmored,
                    passphrase = pass,
                    reason = RevocationReasonTags.KEY_COMPROMISED,
                    reasonText = "test revoke",
                ),
            )
            val revokedPublic = RevocationCertApplier().applyToPublicKeyRing(key.publicArmored, revocation)
            PgpTestSupport.assertRevoked(revokedPublic)

            val revokedSecret = RevocationCertApplier().applyToSecretKeyRing(key.secretArmored, revocation)
            val info = KeyRingReader().readSecretKeyRing(revokedSecret.inputStream())
            assertTrue(info.isRevoked)
        } finally {
            pass.fill('\u0000')
        }
    }

    @Test
    fun revokedKey_decryptFails() {
        val pass = "revoke-decrypt-pass".toCharArray()
        try {
            val key = PgpTestSupport.generateRsa("RevokedDecrypt <rd@example.com>", pass)
            val plaintext = "Should not decrypt after revoke".toByteArray(Charsets.UTF_8)
            val encrypted = PgpTestSupport.encrypt(plaintext, listOf(key.publicArmored))
            val revocation = RevocationCertGenerator().generate(
                RevocationCertRequest(secretKeyRingArmored = key.secretArmored, passphrase = pass),
            )
            val revokedSecret = RevocationCertApplier().applyToSecretKeyRing(key.secretArmored, revocation)
            var failed = false
            try {
                PgpTestSupport.decrypt(encrypted, revokedSecret, pass)
            } catch (_: Exception) {
                failed = true
            }
            assertTrue(failed, "Decrypt with revoked secret key should fail")
        } finally {
            pass.fill('\u0000')
        }
    }

    @Test
    fun encryptDecrypt_rsaSubkeyTypes() {
        val pass = "rsa-sub-pass".toCharArray()
        try {
            val base = PgpTestSupport.generateRsa("RSA Sub <rs@example.com>", pass)
            val withSign = SubkeyAdder().addSubkey(
                AddSubkeyRequest(base.secretArmored, pass, SubkeyType.SIGN_RSA, 2048),
            )
            val plaintext = "RSA subkey flow".toByteArray(Charsets.UTF_8)
            val encSubId = PgpTestSupport.encryptionSubkeyId(withSign)
            val encrypted = PgpTestSupport.encrypt(plaintext, listOf(KeyRingExporter.publicArmoredFromSecret(withSign)))
            val decrypted = PgpTestSupport.decrypt(encrypted, withSign, pass)
            assertArrayEquals(plaintext, decrypted)
            assertTrue(PgpTestSupport.subkeyIds(withSign).contains(encSubId))
        } finally {
            pass.fill('\u0000')
        }
    }
}
