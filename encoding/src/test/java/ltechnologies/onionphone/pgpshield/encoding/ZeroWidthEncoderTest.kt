package ltechnologies.onionphone.pgpshield.encoding

import org.junit.Assert.assertEquals
import org.junit.Test

class ZeroWidthEncoderTest {
    @Test
    fun roundTrip() {
        val original = "Secret message 🔐"
        val encoded = ZeroWidthEncoder.encode(original, visiblePrefix = "Hello ")
        val decoded = ZeroWidthEncoder.decode(encoded)
        assertEquals(original, decoded)
    }
}
