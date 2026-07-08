package ltechnologies.onionphone.pgpshield.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyserverClientTest {
    private val base = "https://keys.openpgp.org"

    @Test
    fun buildLookupUrl_email_usesVks() {
        val url = KeyserverClient.buildLookupUrl(base, "user@example.org")
        assertEquals("$base/vks/v1/by-email/user%40example.org", url)
    }

    @Test
    fun buildLookupUrl_fingerprint_uppercasesForVks() {
        val fp = "8e8c33fa4626337976d97978069c0c348dd82c19"
        val url = KeyserverClient.buildLookupUrl(base, fp)
        assertEquals("$base/vks/v1/by-fingerprint/8E8C33FA4626337976D97978069C0C348DD82C19", url)
    }

    @Test
    fun buildLookupUrl_keyId_usesVksByKeyId() {
        val url = KeyserverClient.buildLookupUrl(base, "0x069C0C348DD82C19")
        assertEquals("$base/vks/v1/by-keyid/069C0C348DD82C19", url)
    }

    @Test
    fun buildLookupUrl_negativeJavaKeyId_usesUnsignedHex() {
        val negativeKeyId = -7316947281898173309L
        val url = KeyserverClient.buildLookupUrl(base, "0x${negativeKeyId.toString(16)}")
        assertTrue(url.contains("/vks/v1/by-keyid/"))
        assertEquals(
            "$base/vks/v1/by-keyid/${KeyserverClient.keyIdToHex(negativeKeyId)}",
            url,
        )
    }

    @Test
    fun keyIdToHex_isUnsigned() {
        val id = -7316947281898173309L
        assertEquals("9A74FB36C6330C83", KeyserverClient.keyIdToHex(id))
    }
}
