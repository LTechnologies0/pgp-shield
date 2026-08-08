package ltechnologies.onionphone.pgpshield.data.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class SensitiveMemoryTest {
    @Test
    fun wipe_clearsCharAndByteBuffers() {
        val chars = charArrayOf('s', 'e', 'c', 'r', 'e', 't')
        val bytes = byteArrayOf(1, 2, 3, 4)
        SensitiveMemory.wipe(chars)
        SensitiveMemory.wipe(bytes)
        assertArrayEquals(CharArray(6) { '\u0000' }, chars)
        assertArrayEquals(ByteArray(4) { 0 }, bytes)
    }

    @Test
    fun useAndWipe_runsBlockThenClears() {
        val secret = "passphrase".toCharArray()
        val result = SensitiveMemory.useAndWipe(secret) { it.concatToString() }
        assertEquals("passphrase", result)
        assertArrayEquals(CharArray(secret.size) { '\u0000' }, secret)
    }

    @Test
    fun charArrayEncoder_roundTrip() {
        val original = "αβγ-pass".toCharArray()
        val encoded = CharArrayEncoder.encodeUtf8(original)
        val decoded = CharArrayEncoder.decodeUtf8(encoded)
        assertArrayEquals(original, decoded)
        SensitiveMemory.wipe(original, decoded)
        SensitiveMemory.wipe(encoded)
    }
}
