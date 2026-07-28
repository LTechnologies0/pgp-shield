package ltechnologies.onionphone.pgpshield.engine

import java.nio.charset.StandardCharsets
import java.nio.file.Files
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIf

/**
 * Ensures ECDSA certifications use a digest large enough for the curve so GnuPG,
 * Kleopatra, and OpenKeychain can import the armored public key.
 */
class EcdsaHashInteropTest {
    @Test
    fun p521_selfSignaturesUseSha512() {
        val armored = generatePublicArmored(KeyAlgorithmType.ECDSA_P521, "P521 <p521@example.com>")
        assertSignatureDigests(armored, HashAlgorithmTags.SHA512)
    }

    @Test
    fun p384_selfSignaturesUseSha384() {
        val armored = generatePublicArmored(KeyAlgorithmType.ECDSA_P384, "P384 <p384@example.com>")
        assertSignatureDigests(armored, HashAlgorithmTags.SHA384)
    }

    @Test
    fun p256_selfSignaturesUseSha256() {
        val armored = generatePublicArmored(KeyAlgorithmType.ECDSA_P256, "P256 <p256@example.com>")
        assertSignatureDigests(armored, HashAlgorithmTags.SHA256)
    }

    @Test
    @EnabledIf("gpgAvailable")
    fun p521_publicKeyImportsIntoGnuPg() {
        val armored = generatePublicArmored(KeyAlgorithmType.ECDSA_P521, "GpgP521 <gpg-p521@example.com>")
        val gnupgHome = Files.createTempDirectory("pgp-shield-gnupg")
        try {
            val keyFile = gnupgHome.resolve("p521.asc")
            Files.write(keyFile, armored)
            val process = ProcessBuilder(
                "gpg",
                "--batch",
                "--homedir",
                gnupgHome.toString(),
                "--import",
                keyFile.toString(),
            ).redirectErrorStream(true).start()
            val output = process.inputStream.readBytes().toString(StandardCharsets.UTF_8)
            val exit = process.waitFor()
            assertFalse(
                output.contains("requires a 512 bit or larger hash"),
                "GnuPG rejected P-521 digest: $output",
            )
            assertFalse(
                output.contains("bad signatures"),
                "GnuPG reported bad signatures: $output",
            )
            assertFalse(
                output.contains("contains no user ID"),
                "GnuPG dropped user IDs: $output",
            )
            assertEquals(0, exit, "gpg --import failed: $output")
            assertTrue(
                output.contains("imported") || output.contains("unchanged"),
                "Unexpected gpg import output: $output",
            )
        } finally {
            gnupgHome.toFile().deleteRecursively()
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

    private fun generatePublicArmored(type: KeyAlgorithmType, userId: String): ByteArray {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "interop-pass-$type".toCharArray()
        return try {
            KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = userId,
                    passphrase = passphrase,
                    algorithmType = type,
                ),
            ).publicArmored
        } finally {
            passphrase.fill('\u0000')
        }
    }

    private fun assertSignatureDigests(publicArmored: ByteArray, expectedHash: Int) {
        val ring = PGPUtil.getDecoderStream(publicArmored.inputStream()).use { input ->
            PGPObjectFactory(input, JcaKeyFingerprintCalculator()).nextObject() as PGPPublicKeyRing
        }
        val digests = mutableListOf<Int>()
        val keys = ring.publicKeys
        while (keys.hasNext()) {
            val key = keys.next()
            val sigs = key.signatures
            while (sigs.hasNext()) {
                val sig = sigs.next() as PGPSignature
                digests += sig.hashAlgorithm
            }
        }
        assertTrue(digests.isNotEmpty(), "expected self-signatures on generated ring")
        digests.forEach { digest ->
            assertEquals(expectedHash, digest, "unexpected signature digest algorithm")
        }
    }
}
