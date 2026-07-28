package ltechnologies.onionphone.pgpshield.data

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyserverClientTest {
    private val client = KeyserverClient()
    private val base = "https://keyserver.ubuntu.com"

    @Test
    fun buildLookupUrl_email_prefersVksThenHkpGet() {
        val urls = KeyserverClient.lookupUrls(base, "user@example.org")
        assertEquals("$base/vks/v1/by-email/user%40example.org", urls[0])
        assertTrue(urls.any { it.contains("/pks/lookup?op=get") && it.contains("user%40example.org") })
        assertEquals(urls[0], KeyserverClient.buildLookupUrl(base, "user@example.org"))
    }

    @Test
    fun filterRelevantHits_dropsUidLessJunk() {
        val junk = listOf(
            KeyserverSearchHit("AAAAAAAA", null, emptyList()),
            KeyserverSearchHit("BBBBBBBB", null, emptyList()),
        )
        assertTrue(client.filterRelevantHits(junk, "wk@gnupg.org").isEmpty())
    }

    @Test
    fun filterRelevantHits_keepsMatchingEmail() {
        val hits = listOf(
            KeyserverSearchHit("AAAA", null, listOf("Werner Koch <wk@gnupg.org>")),
            KeyserverSearchHit("BBBB", null, listOf("Other <other@example.org>")),
        )
        val filtered = client.filterRelevantHits(hits, "wk@gnupg.org")
        assertEquals(1, filtered.size)
        assertEquals("AAAA", filtered[0].fingerprint)
    }

    @Test
    fun buildLookupUrl_fingerprint_uppercasesForVks() {
        val fp = "8e8c33fa4626337976d97978069c0c348dd82c19"
        val url = KeyserverClient.buildLookupUrl(base, fp)
        assertEquals("$base/vks/v1/by-fingerprint/8E8C33FA4626337976D97978069C0C348DD82C19", url)
    }

    @Test
    fun buildLookupUrl_keyId_usesHkpGet() {
        val url = KeyserverClient.buildLookupUrl(base, "0x069C0C348DD82C19")
        assertEquals("$base/pks/lookup?op=get&options=mr&search=0x069C0C348DD82C19", url)
    }

    @Test
    fun buildLookupUrl_negativeJavaKeyId_usesUnsignedHex() {
        val negativeKeyId = -7316947281898173309L
        val url = KeyserverClient.buildLookupUrl(base, "0x${negativeKeyId.toString(16)}")
        assertTrue(url.contains("/pks/lookup?op=get"))
        assertEquals(
            "$base/pks/lookup?op=get&options=mr&search=0x${KeyserverClient.keyIdToHex(negativeKeyId)}",
            url,
        )
    }

    @Test
    fun keyIdToHex_isUnsigned() {
        val id = -7316947281898173309L
        assertEquals("9A74FB36C6330C83", KeyserverClient.keyIdToHex(id))
    }

    @Test
    fun parseHkpMachineReadableIndex_extractsPubAndUid() {
        val body = """
            info:1:2
            pub:C5B2D126D005D38D561E7B7D61D7A5A297D2F600:1:2048:1577112106::
            uid:Alice%20%3Calice%40example.org%3E:1577112106::
            pub:A96626195A8A7DBC8CFF6DB2F609FF001EB4A8B0:1:2048:1577111093::
            uid:Bob%20%3Cbob%40example.org%3E:1577111093::
        """.trimIndent()
        val hits = client.parseHkpMachineReadableIndex(body)
        assertEquals(2, hits.size)
        assertEquals("C5B2D126D005D38D561E7B7D61D7A5A297D2F600", hits[0].fingerprint)
        assertTrue(hits[0].userIds.any { it.contains("alice@example.org") })
        assertEquals("A96626195A8A7DBC8CFF6DB2F609FF001EB4A8B0", hits[1].fingerprint)
    }

    @Test
    fun candidateBases_putsPreferredFirst() {
        val bases = KeyserverClient.candidateBases("https://keys.mailvelope.com")
        assertEquals("https://keys.mailvelope.com", bases.first())
        assertTrue(bases.contains("https://keyserver.ubuntu.com"))
    }
}
