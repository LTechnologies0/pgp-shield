package ltechnologies.onionphone.pgpshield.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Lightweight SOP-style / interop harness: asserts policy surfaces and PQC fail-closed.
 */
class SopInteropHarnessTest {
    @Test
    fun interopProfiles_coverModernLibreAndLegacy() {
        assertTrue(InteropProfile.entries.contains(InteropProfile.RFC9580_MODERN))
        assertTrue(InteropProfile.entries.contains(InteropProfile.LIBREPGP_GNUPG))
        assertTrue(InteropProfile.entries.contains(InteropProfile.LEGACY_MDC))
        assertEquals(MessageIntegrity.SEIPD_V2_AEAD, InteropProfile.RFC9580_MODERN.defaultIntegrity())
        assertEquals(MessageIntegrity.LIBREPGP_V5_AEAD, InteropProfile.LIBREPGP_GNUPG.defaultIntegrity())
        assertEquals(MessageIntegrity.MDC, InteropProfile.LEGACY_MDC.defaultIntegrity())
    }

    @Test
    fun messageIntegrity_includesLibrePgpV5() {
        assertTrue(MessageIntegrity.entries.contains(MessageIntegrity.LIBREPGP_V5_AEAD))
    }

    @Test
    fun pqc_failClosed_whenUnsupported() {
        assertFalse(PqcSupport.isGenerationSupported)
        assertThrows(PgpException::class.java) {
            PqcSupport.requireAvailable()
        }
    }

    @Test
    fun features_or_forSeipdV2() {
        BouncyCastleProviderHolder.ensureRegistered()
        val pass = "sop-feat".toCharArray()
        val key = KeyGenerator().generateKeyRingBlocking(
            GenerateKeyRequest("Sop <s@e.com>", pass, KeyAlgorithmType.ED25519),
        )
        val caps = PgpRecipientCapabilities.fromArmoredRing(key.publicArmored)
        assertTrue(caps.supportsSeipdV2)
        assertTrue(caps.supportsAeadEncryptedData)
    }
}
