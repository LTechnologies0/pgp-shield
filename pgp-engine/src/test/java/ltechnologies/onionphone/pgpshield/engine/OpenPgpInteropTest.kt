package ltechnologies.onionphone.pgpshield.engine

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIf

/**
 * Cross-checks OpenPGP outputs against GnuPG and RFC 4880 interoperability rules.
 */
class OpenPgpInteropTest {
    @Test
    fun cleartextCanonicalization_matchesGnuPgRules() {
        // No trailing CRLF after the last line (BC ClearSignedFileProcessor / GnuPG).
        assertEquals("Signed line", PgpCleartext.canonicalize("Signed line\n").toString(Charsets.UTF_8))
        assertEquals("line1\r\nline2", PgpCleartext.canonicalize("line1\nline2  \n").toString(Charsets.UTF_8))
        assertEquals("a\r\n\r\nb", PgpCleartext.canonicalize("a\n\nb\n").toString(Charsets.UTF_8))
    }

    @Test
    fun cleartextCanonicalization_isIdempotent() {
        val once = PgpCleartext.canonicalize("Signed line\n")
        val twice = PgpCleartext.canonicalize(once)
        assertEquals("Signed line", once.toString(Charsets.UTF_8))
        assertArrayEquals(once, twice)
    }

    @Test
    fun generatedKey_advertisesPreferencesAndMdcFeature() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "prefs-pass".toCharArray()
        val generated = try {
            KeyGenerator().generateKeyRing(
                GenerateKeyRequest("Prefs <p@example.com>", pass, KeyAlgorithmType.ED25519),
            )
        } finally {
            pass.fill('\u0000')
        }
        val ring = PGPUtil.getDecoderStream(generated.publicArmored.inputStream()).use { input ->
            PGPObjectFactory(input, JcaKeyFingerprintCalculator()).nextObject() as PGPPublicKeyRing
        }
        val master = ring.publicKey
        val selfSig = master.getSignaturesForID("Prefs <p@example.com>").asSequence()
            .filterIsInstance<PGPSignature>()
            .first { it.keyID == master.keyID }

        val hashed = selfSig.hashedSubPackets
        val features = hashed.features
        assertNotNull(features, "self-signature must advertise Features")
        assertTrue(features!!.supportsModificationDetection(), "Features must include MDC")
        assertTrue(hashed.preferredSymmetricAlgorithms.isNotEmpty(), "missing preferred symmetric algorithms")
        assertTrue(hashed.preferredHashAlgorithms.isNotEmpty(), "missing preferred hash algorithms")
        assertTrue(hashed.preferredCompressionAlgorithms.isNotEmpty(), "missing preferred compression algorithms")
    }

    @Test
    fun androidUi_excludesNonPortableEd448() {
        assertFalse(KeyAlgorithmType.ED448 in PgpAlgorithmPolicy.androidGeneratableKeyTypes)
        assertFalse(SubkeyType.ENCRYPT_X448 in PgpAlgorithmPolicy.androidGeneratableSubkeyTypes)
        assertFalse(SubkeyType.SIGN_ED448 in PgpAlgorithmPolicy.androidGeneratableSubkeyTypes)
    }

    @Test
    @EnabledIf("gpgAvailable")
    fun cleartextSignature_verifiesInGnuPg() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "gpg-clear-pass".toCharArray()
        val gnupgHome = Files.createTempDirectory("pgp-shield-cleartext")
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest("Clear <c@example.com>", pass, KeyAlgorithmType.ED25519),
            )
            val signed = PgpSigner().sign(
                SignRequest(
                    data = "Hello interoperable world\nSecond line\n".toByteArray(Charsets.UTF_8),
                    secretKeyRingArmored = generated.secretArmored,
                    passphrase = pass,
                ),
            )
            val pub = gnupgHome.resolve("pub.asc")
            val msg = gnupgHome.resolve("signed.asc")
            Files.write(pub, generated.publicArmored)
            Files.write(msg, signed.output)

            val importProc = ProcessBuilder(
                "gpg", "--batch", "--homedir", gnupgHome.toString(), "--import", pub.toString(),
            ).redirectErrorStream(true).start()
            val importOut = importProc.inputStream.readBytes().toString(StandardCharsets.UTF_8)
            assertTrue(importProc.waitFor() == 0, "gpg import failed: $importOut")

            val verifyProc = ProcessBuilder(
                "gpg", "--batch", "--homedir", gnupgHome.toString(), "--verify", msg.toString(),
            ).redirectErrorStream(true).start()
            val verifyOut = verifyProc.inputStream.readBytes().toString(StandardCharsets.UTF_8)
            assertFalse(verifyOut.contains("BAD signature"), "GnuPG rejected cleartext: $verifyOut")
            assertTrue(
                verifyOut.contains("Good signature") || verifyProc.waitFor() == 0,
                "expected good cleartext signature: $verifyOut",
            )
        } finally {
            pass.fill('\u0000')
            gnupgHome.toFile().deleteRecursively()
        }
    }

    @Test
    fun p521_preferredHashStartsWithSha512() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "p521-pref".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest("P521 <p521@example.com>", pass, KeyAlgorithmType.ECDSA_P521),
            )
            val ring = PGPUtil.getDecoderStream(generated.publicArmored.inputStream()).use { input ->
                PGPObjectFactory(input, JcaKeyFingerprintCalculator()).nextObject() as PGPPublicKeyRing
            }
            val prefs = PgpAlgorithmPolicy.preferredHashAlgorithms(ring.publicKey)
            assertEquals(HashAlgorithmTags.SHA512, prefs.first())
        } finally {
            pass.fill('\u0000')
        }
    }

    companion object {
        @JvmStatic
        fun gpgAvailable(): Boolean =
            try {
                ProcessBuilder("gpg", "--version").start().waitFor() == 0
            } catch (_: Exception) {
                false
            }
    }
}
