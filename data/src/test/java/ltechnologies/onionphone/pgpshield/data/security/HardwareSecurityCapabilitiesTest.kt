package ltechnologies.onionphone.pgpshield.data.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class HardwareSecurityCapabilitiesTest {
    @Test
    fun report_includesMemtagFields() {
        val context = RuntimeEnvironment.getApplication()
        val report = HardwareSecurityCapabilities.report(context)
        assertTrue(report.summary.isNotBlank())
        assertTrue(report.memtagRequested.isNotBlank())
        assertTrue(report.memtagRuntime.isNotBlank())
        assertFalse(report.strongBoxKeystore)
    }

    @Test
    fun vaultAliases_areDistinct() {
        assertTrue(VaultMasterKeyFactory.ALIAS_V2 != VaultMasterKeyFactory.ALIAS_PREFS)
        assertTrue(VaultMasterKeyFactory.ALIAS_V2.startsWith("_pgp_shield"))
    }

    @Test
    fun readMemtagRuntime_doesNotThrow() {
        val mode = HardwareSecurityCapabilities.readMemtagRuntime()
        assertTrue(mode.isNotBlank())
    }
}
