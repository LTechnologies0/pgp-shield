package ltechnologies.onionphone.pgpshield.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class TorSocksTest {
    @Test
    fun productionDefaults_areOnionVpnLoopback() {
        assertFalse(TorSocks.bypassForTests)
        assertEquals("127.0.0.1", TorSocks.HOST)
        assertEquals(18202, TorSocks.PORT)
    }
}
