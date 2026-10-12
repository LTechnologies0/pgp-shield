package ltechnologies.onionphone.pgpshield.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class KeyIdParserTest {
    @Test
    fun parse_negativeJavaLongHex_usesUnsignedBits() {
        val negative = -7316947281898173309L
        assertEquals(negative, KeyIdParser.parse("9A74FB36C6330C83"))
        assertEquals(negative, KeyIdParser.parse("0x9A74FB36C6330C83"))
    }

    @Test
    fun parse_signedDecimalNegative_keepsBits() {
        assertEquals(-1L, KeyIdParser.parse("-1"))
    }

    @Test
    fun parse_empty_returnsNull() {
        assertNull(KeyIdParser.parse("   "))
        assertNull(KeyIdParser.parse("0x"))
    }
}
