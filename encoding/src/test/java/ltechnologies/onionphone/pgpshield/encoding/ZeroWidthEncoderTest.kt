package ltechnologies.onionphone.pgpshield.encoding

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
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
    fun visibleCover_stripsZeroWidthFrame() {
        val encoded = ZeroWidthEncoder.encode("payload", visiblePrefix = "Cover")
        assertEquals("Cover", ZeroWidthEncoder.visibleCover(encoded))
    }

    @Test
    fun decode_toleratesTrailingJunk() {
        val encoded = ZeroWidthEncoder.encode("hi", visiblePrefix = "x") + " 🙂 footer"
        assertEquals("hi", ZeroWidthEncoder.decode(encoded))
    }

    @Test
    fun reencode_doesNotNestFrames() {
        val once = ZeroWidthEncoder.encode("secret", visiblePrefix = "decoy")
        val cover = ZeroWidthEncoder.visibleCover(once)
        val payload = ZeroWidthEncoder.decode(once) ?: cover
        val twice = ZeroWidthEncoder.encode(payload, visiblePrefix = cover)
        assertEquals("secret", ZeroWidthEncoder.decode(twice))
        assertEquals("decoy", ZeroWidthEncoder.visibleCover(twice))
    }

    @Test
    fun decode_rejectsMissingMagic() {
        assertNull(ZeroWidthEncoder.decode("plain text only"))
    }
}
