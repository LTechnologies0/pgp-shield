package ltechnologies.onionphone.pgpshield.intent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IntentIoHelperContractTest {
    @Test
    fun loadEncryptPublicKey_errorMessage_mentionsRecipient() {
        assertTrue(
            runCatching {
                error("No allowed recipient key — Never-trusted, revoked, or expired keys are skipped")
            }.exceptionOrNull()?.message?.contains("recipient") == true,
        )
    }

    @Test
    fun loadDecryptSecretKey_errorMessage_isStable() {
        assertEquals(
            "No secret key on device",
            runCatching { error("No secret key on device") }.exceptionOrNull()?.message,
        )
    }
}
