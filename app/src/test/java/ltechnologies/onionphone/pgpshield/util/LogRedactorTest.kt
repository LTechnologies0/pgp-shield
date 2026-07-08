package ltechnologies.onionphone.pgpshield.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LogRedactorTest {
    @Test
    fun redact_masks_passphrase_and_armor() {
        val raw = "passphrase=secret -----BEGIN PGP PRIVATE KEY BLOCK-----"
        assertEquals("[REDACTED]", LogRedactor.redact(raw))
    }

    @Test
    fun looksSensitive_detects_fingerprint() {
        assertTrue(LogRedactor.looksSensitive("fp ABCDEF0123456789ABCDEF0123456789ABCDEF01"))
    }

    @Test
    fun safeMessage_blocks_sensitive_exception_text() {
        val msg = CryptoErrors.safeMessage(
            IllegalStateException("passphrase mismatch for -----BEGIN PGP"),
            "fallback",
        )
        assertEquals("fallback", msg)
    }
}
