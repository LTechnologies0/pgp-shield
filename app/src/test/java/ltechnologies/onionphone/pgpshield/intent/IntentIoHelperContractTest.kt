package ltechnologies.onionphone.pgpshield.intent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class IntentIoHelperContractTest {
    @Test
    fun loadEncryptPublicKey_errorMessage_isStable() {
        assertTrue(
            runCatching {
                error("No recipient key configured")
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
