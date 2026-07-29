package ltechnologies.onionphone.pgpshield.encoding

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class PaddingEncoderTest {
    private val encoder = PaddingEncoder()

    @Test
    fun roundTrip_lf() {
        val encoded = encoder.encode("secret", "Title", "Body")
        assertEquals("secret", encoder.decode(encoded, "Title", "Body"))
    }

    @Test
    fun decode_acceptsMessengerCrlf() {
        val encoded = "Title\r\n\r\nBody\r\n\r\nsecret"
        assertEquals("secret", encoder.decode(encoded, "Title", "Body"))
    }

    @Test
    fun decode_rejectsWrongTemplate() {
        val encoded = encoder.encode("secret", "Title", "Body")
        assertNull(encoder.decode(encoded, "Other", "Body"))
    }
}
