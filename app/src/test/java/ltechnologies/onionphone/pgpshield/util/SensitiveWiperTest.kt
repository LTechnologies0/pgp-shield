package ltechnologies.onionphone.pgpshield.util

import org.junit.Assert.assertEquals
import org.junit.Test

class SensitiveWiperTest {
    @Test
    fun wipe_zeroes_char_array() {
        val buf = charArrayOf('s', 'e', 'c', 'r', 'e', 't')
        SensitiveWiper.wipe(buf)
        assertEquals('\u0000', buf[0])
        assertEquals('\u0000', buf[buf.lastIndex])
    }
}
