package ltechnologies.onionphone.pgpshield.api

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InMemoryPgpShieldClientTest {
    private val client = InMemoryPgpShieldClient()
    private val caller = CallerIdentity("dev.test", 0)

    @Test
    fun encrypt_roundTripsPlaintext() = runBlocking {
        val data = "hello".toByteArray()
        val result = client.encrypt(
            EncryptRequestParcel(caller, data, longArrayOf(1L)),
        )
        assertTrue(result.success)
        assertEquals("hello", String(result.output!!))
    }

    @Test
    fun listKeys_returnsStubKey() = runBlocking {
        val keys = client.listKeys("dev.test")
        assertEquals(1, keys.size)
        assertEquals(1L, keys[0].masterKeyId)
    }
}
