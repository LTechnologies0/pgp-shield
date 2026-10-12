package ltechnologies.onionphone.pgpshield.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class OnePassSignaturePairingTest {
    @Test
    fun pairIndices_reversesSignatureOrder() {
        assertEquals(listOf(0 to 2, 1 to 1, 2 to 0), OnePassSignaturePairing.pairIndices(3, 3))
        assertEquals(listOf(0 to 0), OnePassSignaturePairing.pairIndices(1, 1))
    }

    @Test
    fun pairIndices_mismatch_throws() {
        assertThrows(PgpException::class.java) {
            OnePassSignaturePairing.pairIndices(2, 1)
        }
        assertThrows(PgpException::class.java) {
            OnePassSignaturePairing.pairIndices(0, 0)
        }
    }
}
