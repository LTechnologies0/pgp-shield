package ltechnologies.onionphone.pgpshield.util

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class CallerVerifierTest {
    @Test
    fun assertCallerUidNotProcess_rejectsCollapsedUid() {
        val error = assertThrows(IllegalArgumentException::class.java) {
            CallerVerifier.assertCallerUidNotProcess(
                callingUid = 1000,
                processUid = 1000,
                claimedPackage = "org.example.mail",
                ownPackage = "ltechnologies.onionphone.pgpshield",
            )
        }
        assertEquals("Caller UID collapsed to process UID", error.message)
    }

    @Test
    fun assertCallerUidNotProcess_allowsSameUidForOwnPackage() {
        CallerVerifier.assertCallerUidNotProcess(
            callingUid = 1000,
            processUid = 1000,
            claimedPackage = "ltechnologies.onionphone.pgpshield",
            ownPackage = "ltechnologies.onionphone.pgpshield",
        )
    }

    @Test
    fun assertCallerUidNotProcess_allowsDistinctBinderUid() {
        CallerVerifier.assertCallerUidNotProcess(
            callingUid = 10123,
            processUid = 1000,
            claimedPackage = "org.example.mail",
            ownPackage = "ltechnologies.onionphone.pgpshield",
        )
    }
}
