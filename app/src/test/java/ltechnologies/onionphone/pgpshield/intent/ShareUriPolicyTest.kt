package ltechnologies.onionphone.pgpshield.intent

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ShareUriPolicyTest {
    @Test
    fun contentScheme_isAllowed() {
        assertTrue(ShareUriPolicy.isAllowedContentScheme("content"))
        assertTrue(ShareUriPolicy.isAllowedContentScheme("CONTENT"))
    }

    @Test
    fun fileAndOtherSchemes_areDenied() {
        assertFalse(ShareUriPolicy.isAllowedContentScheme("file"))
        assertFalse(ShareUriPolicy.isAllowedContentScheme("http"))
        assertFalse(ShareUriPolicy.isAllowedContentScheme(null))
        assertFalse(ShareUriPolicy.isAllowedContentScheme(""))
    }
}
