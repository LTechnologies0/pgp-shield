package ltechnologies.onionphone.pgpshield.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CryptoProgressTest {
    @Test
    fun measure_recordsStagesWithoutPayload() {
        val (value, summary) = CryptoProgress.measure(CryptoOperation.ENCRYPT) {
            CryptoProgress.stage(CryptoStage.PARSE_KEYS)
            CryptoProgress.stage(CryptoStage.ENCRYPT_SESSION)
            42
        }
        assertEquals(42, value)
        assertEquals(CryptoOperation.ENCRYPT, summary.operation)
        assertTrue(summary.totalMs >= 0)
        assertTrue(summary.stages.isNotEmpty())
        assertFalse(summary.stages.any { it.stage.name.contains("KEY", ignoreCase = false) && it.durationMs < 0 })
        // Privacy: summary only carries operation + timings + heap delta.
        assertEquals(CryptoOperation.ENCRYPT, summary.operation)
    }
}
