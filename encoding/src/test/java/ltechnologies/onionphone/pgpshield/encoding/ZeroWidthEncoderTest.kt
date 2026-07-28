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

    @Test
    fun containsPayloadDetectsEncodedAndIgnoresPlain() {
        val encoded = ZeroWidthEncoder.encode("secret", visiblePrefix = "Hello")
        assertEquals(true, ZeroWidthEncoder.containsPayload(encoded))
        assertEquals(false, ZeroWidthEncoder.containsPayload("Hello plain text"))
    }
}
