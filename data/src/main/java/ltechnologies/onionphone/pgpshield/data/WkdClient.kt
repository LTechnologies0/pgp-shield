package ltechnologies.onionphone.pgpshield.data

/**
 * Web Key Directory (WKD) client — RFC 7929 / draft-koch-openpgp-webkey-service.
 */

import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.security.MessageDigest
import java.util.Locale
import javax.inject.Inject
import javax.inject.Singleton
import ltechnologies.onionphone.pgpshield.engine.PgpException
import ltechnologies.onionphone.pgpshield.engine.PgpIo

@Singleton
class WkdClient @Inject constructor() {
    /**
     * Fetches an armored public key for [email] via advanced then direct WKD URL.
     */
    fun fetchByEmail(email: String): ByteArray {
        val trimmed = email.trim().lowercase(Locale.ROOT)
        require(trimmed.contains('@')) { "WKD requires an email address" }
        val local = trimmed.substringBefore('@')
        val domain = trimmed.substringAfter('@')
        val localHash = zBase32(sha1(local.toByteArray(Charsets.UTF_8)))
        val advanced = "https://openpgpkey.$domain/.well-known/openpgpkey/$domain/hu/$localHash"
        val direct = "https://$domain/.well-known/openpgpkey/hu/$localHash"
        return runCatching { fetchUrl(advanced) }
            .recoverCatching { fetchUrl(direct) }
            .getOrElse { throw PgpException("WKD lookup failed for $email: ${it.message}", cause = it) }
    }

    private fun fetchUrl(url: String, redirectDepth: Int = 0): ByteArray {
        require(url.startsWith("https://", ignoreCase = true)) { "WKD requires HTTPS" }
        require(redirectDepth <= 3) { "WKD too many redirects" }
        // Do not auto-follow redirects: Location could leave HTTPS (SSRF / downgrade).
        val conn = (URI(url).toURL().openConnection() as HttpURLConnection).apply {
            requestMethod = "GET"
            connectTimeout = 12_000
            readTimeout = 20_000
            instanceFollowRedirects = false
            setRequestProperty("Accept", "application/octet-stream, application/pgp-keys, */*")
        }
        try {
            val code = conn.responseCode
            if (code in 300..399) {
                val location = conn.getHeaderField("Location")
                    ?: throw PgpException("WKD redirect without Location for $url")
                val next = URI(url).resolve(location).toString()
                if (!next.startsWith("https://", ignoreCase = true)) {
                    throw PgpException("WKD refused non-HTTPS redirect to $next")
                }
                return fetchUrl(next, redirectDepth + 1)
            }
            if (code !in 200..299) {
                throw PgpException("WKD HTTP $code for $url")
            }
            val bytes = conn.inputStream.use { input ->
                ByteArrayOutputStream().use { out ->
                    PgpIo.copyLimited(input, out)
                    out.toByteArray()
                }
            }
            if (bytes.isEmpty()) throw PgpException("WKD empty response")
            return bytes
        } finally {
            conn.disconnect()
        }
    }

    private fun sha1(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-1").digest(data)

    /** OpenPGP WKD z-base-32 (RFC 6189 alphabet). */
    private fun zBase32(data: ByteArray): String {
        val alphabet = "ybndrfg8ejkmcpqxot1uwisza345h769"
        val sb = StringBuilder()
        var buffer = 0
        var bitsLeft = 0
        for (b in data) {
            buffer = (buffer shl 8) or (b.toInt() and 0xff)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                bitsLeft -= 5
                sb.append(alphabet[(buffer shr bitsLeft) and 0x1f])
            }
        }
        if (bitsLeft > 0) {
            sb.append(alphabet[(buffer shl (5 - bitsLeft)) and 0x1f])
        }
        return sb.toString()
    }
}
