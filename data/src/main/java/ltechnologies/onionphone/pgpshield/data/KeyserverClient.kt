package ltechnologies.onionphone.pgpshield.data

import ltechnologies.onionphone.pgpshield.engine.KeyRingReader
import ltechnologies.onionphone.pgpshield.engine.PgpException
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import javax.inject.Inject
import javax.inject.Singleton
import org.json.JSONObject

/**
 * A single hit from an HKP/VKS keyserver search (before import).
 *
 * @property fingerprint Full or truncated fingerprint hex (uppercase).
 * @property keyId 64-bit key id when parseable from fingerprint / index.
 * @property userIds User ID strings associated with this pubkey.
 * @property createdEpochSec Creation time from HKP index, if present.
 * @property algorithm OpenPGP algorithm id from HKP index, if present.
 * @property bitLength Key bit length from HKP index, if present.
 */
data class KeyserverSearchHit(
    val fingerprint: String,
    val keyId: Long?,
    val userIds: List<String>,
    val createdEpochSec: Long? = null,
    val algorithm: Int? = null,
    val bitLength: Int? = null,
)

/**
 * HTTP client for OpenPGP keyserver lookup, search, and upload.
 *
 * Supports VKS (keys.openpgp.org) and HKP (Hockeypuck / SKS-style) endpoints.
 * Search uses HKP `op=index&options=mr` with VKS fallbacks for email/fingerprint.
 * Upload prefers VKS JSON then falls back to HKP `/pks/add`.
 */
@Singleton
class KeyserverClient @Inject constructor() {
    /**
     * Searches a keyserver for keys matching [query] without importing them.
     *
     * Tries HKP machine-readable index first, then VKS by-email / by-fingerprint
     * when the query looks like an email or fingerprint. Falls back to alternate
     * HKP servers when the primary returns empty / 404.
     */
    fun searchKeys(baseUrl: String, query: String): List<KeyserverSearchHit> {
        val trimmed = query.trim()
        require(trimmed.isNotEmpty()) { "Empty search query" }
        val bases = candidateBases(baseUrl)
        var lastError: Exception? = null
        for (base in bases) {
            try {
                val hits = searchOnBase(base, trimmed)
                if (hits.isNotEmpty()) return hits
            } catch (e: Exception) {
                lastError = e
            }
        }
        if (lastError != null) {
            throw PgpException(
                message = "Keyserver search failed: ${lastError.message ?: lastError.javaClass.simpleName}",
                cause = lastError,
            )
        }
        return emptyList()
    }

    /**
     * Fetches an armored public key from [baseUrl] matching [query].
     *
     * @param baseUrl Keyserver base URL (e.g. `https://keys.openpgp.org`).
     * @param query Email address, 40-hex fingerprint, or 8–16 hex key id.
     * @return Armored PGP public key bytes.
     */
    fun fetchKey(baseUrl: String, query: String): ByteArray {
        val trimmed = query.trim()
        require(trimmed.isNotEmpty()) { "Empty search query" }
        val bases = candidateBases(baseUrl)
        var lastError: Exception? = null
        for (base in bases) {
            for (url in lookupUrls(base.trimEnd('/'), trimmed)) {
                try {
                    val conn = openConnection(url, method = "GET").apply {
                        setRequestProperty("Accept", "application/pgp-keys, application/octet-stream, text/plain, */*")
                    }
                    try {
                        return readArmoredKey(conn)
                    } finally {
                        conn.disconnect()
                    }
                } catch (e: Exception) {
                    lastError = e
                }
            }
        }
        throw PgpException(
            message = "Keyserver fetch failed: ${lastError?.message ?: "no key found"}",
            cause = lastError,
        )
    }

    /**
     * Uploads armored public key material to [baseUrl].
     *
     * Attempts VKS JSON upload first (`/vks/v1/upload`); falls back to HKP `/pks/add`.
     */
    fun uploadPublicKey(baseUrl: String, armoredPublic: ByteArray) {
        val armored = String(armoredPublic, Charsets.UTF_8).trim()
        require(armored.contains("BEGIN PGP PUBLIC")) { "Not armored public key material" }
        val bases = candidateBases(baseUrl)
        var lastError: Exception? = null
        for (base in bases) {
            val trimmedBase = base.trimEnd('/')
            val vksError = runCatching { uploadViaVks(trimmedBase, armored) }
                .exceptionOrNull()
            if (vksError == null) return
            val hkpError = runCatching { uploadViaHkp(trimmedBase, armored) }
                .exceptionOrNull()
            if (hkpError == null) return
            lastError = PgpException(
                "VKS: ${vksError.message}; HKP: ${hkpError.message}",
            )
        }
        throw PgpException(
            message = "Keyserver upload failed (${lastError?.message ?: "unknown"})",
            cause = lastError,
        )
    }

    private fun searchOnBase(base: String, query: String): List<KeyserverSearchHit> {
        val root = base.trimEnd('/')

        // Email / fingerprint / key-id: prefer a direct get. Ubuntu's HKP `op=index`
        // for emails often returns 100 unrelated pubs with no UIDs (SKS dump noise).
        if (query.contains('@') || looksLikeFingerprint(query) || looksLikeKeyId(query)) {
            val direct = runCatching { hitFromFetchedKey(root, query) }.getOrNull()
            if (direct != null) return listOf(direct)
        }

        val hkpHits = runCatching { searchViaHkpIndex(root, query) }.getOrDefault(emptyList())
        val filtered = filterRelevantHits(hkpHits, query)
        if (filtered.isNotEmpty()) return filtered

        return emptyList()
    }

    /**
     * Drops UID-less SKS junk and, for email/name queries, keeps only hits whose
     * user IDs actually contain the query string.
     */
    internal fun filterRelevantHits(hits: List<KeyserverSearchHit>, query: String): List<KeyserverSearchHit> {
        if (hits.isEmpty()) return emptyList()
        val withUids = hits.filter { it.userIds.isNotEmpty() }
        if (withUids.isEmpty()) return emptyList()

        val needle = query.trim().lowercase()
        if (needle.isEmpty()) return withUids

        val matching = withUids.filter { hit ->
            hit.userIds.any { it.lowercase().contains(needle) } ||
                hit.fingerprint.contains(needle.filter { it.isLetterOrDigit() }.uppercase())
        }
        return when {
            matching.isNotEmpty() -> matching
            // Free-text name search: return UID-bearing hits as-is when no substring match
            !needle.contains('@') && !looksLikeFingerprint(needle) && !looksLikeKeyId(needle) -> withUids
            else -> emptyList()
        }
    }

    private fun hitFromFetchedKey(base: String, query: String): KeyserverSearchHit? {
        var lastError: Exception? = null
        for (url in lookupUrls(base, query)) {
            try {
                val conn = openConnection(url, method = "GET").apply {
                    setRequestProperty("Accept", "application/pgp-keys, application/octet-stream, text/plain, */*")
                }
                val armored = try {
                    readArmoredKey(conn)
                } finally {
                    conn.disconnect()
                }
                val info = KeyRingReader().readPublicKeyRing(ByteArrayInputStream(armored))
                val fp = normalizeFingerprint(info.fingerprint)
                return KeyserverSearchHit(
                    fingerprint = fp,
                    keyId = info.masterKeyId,
                    userIds = info.userIds.map { it.userId },
                    createdEpochSec = info.subkeys.firstOrNull()?.creationTime?.epochSecond,
                )
            } catch (e: Exception) {
                lastError = e
            }
        }
        if (lastError != null) throw lastError
        return null
    }

    private fun searchViaHkpIndex(base: String, query: String): List<KeyserverSearchHit> {
        val encoded = URLEncoder.encode(query, Charsets.UTF_8)
        val url = "$base/pks/lookup?op=index&options=mr&search=$encoded"
        val conn = openConnection(url, method = "GET").apply {
            setRequestProperty("Accept", "text/plain, */*")
        }
        try {
            val code = conn.responseCode
            if (code == 404) return emptyList()
            if (code !in 200..299) {
                val err = readResponseBody(conn, code).take(200)
                throw PgpException("HKP index HTTP $code${err.takeIf { it.isNotBlank() }?.let { ": $it" } ?: ""}")
            }
            val body = (conn.inputStream ?: return emptyList()).readBytes().toString(Charsets.UTF_8)
            return parseHkpMachineReadableIndex(body)
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Parses HKP `options=mr` index output into [KeyserverSearchHit]s.
     *
     * Format (Hockeypuck / SKS):
     * ```
     * info:1:N
     * pub:fingerprint:algo:bits:created:expires:flags:
     * uid:escaped_uid:created:expires:flags:
     * ```
     */
    internal fun parseHkpMachineReadableIndex(body: String): List<KeyserverSearchHit> {
        val hits = mutableListOf<KeyserverSearchHit>()
        var currentFp: String? = null
        var currentKeyId: Long? = null
        var currentAlgo: Int? = null
        var currentBits: Int? = null
        var currentCreated: Long? = null
        var currentUids = mutableListOf<String>()

        fun flush() {
            val fp = currentFp ?: return
            hits += KeyserverSearchHit(
                fingerprint = fp,
                keyId = currentKeyId,
                userIds = currentUids.toList(),
                createdEpochSec = currentCreated,
                algorithm = currentAlgo,
                bitLength = currentBits,
            )
            currentFp = null
            currentKeyId = null
            currentAlgo = null
            currentBits = null
            currentCreated = null
            currentUids = mutableListOf()
        }

        for (rawLine in body.lineSequence()) {
            val line = rawLine.trim()
            if (line.isEmpty() || line.startsWith("info:")) continue
            val parts = line.split(':')
            when (parts.firstOrNull()) {
                "pub" -> {
                    flush()
                    if (parts.size < 2) continue
                    val fp = parts[1].filter { it.isLetterOrDigit() }.uppercase()
                    if (fp.isEmpty()) continue
                    currentFp = fp
                    currentKeyId = runCatching { fp.takeLast(16).toLong(16) }.getOrNull()
                    currentAlgo = parts.getOrNull(2)?.toIntOrNull()
                    currentBits = parts.getOrNull(3)?.toIntOrNull()
                    currentCreated = parts.getOrNull(4)?.toLongOrNull()
                }
                "uid" -> {
                    if (currentFp == null || parts.size < 2) continue
                    val uid = decodeHkpUid(parts[1])
                    if (uid.isNotBlank()) currentUids += uid
                }
            }
        }
        flush()
        return hits
    }

    private fun decodeHkpUid(escaped: String): String =
        runCatching {
            // HKP uses percent-encoding plus '+' for spaces in some servers
            java.net.URLDecoder.decode(escaped.replace('+', ' '), Charsets.UTF_8)
        }.getOrDefault(escaped)

    private fun uploadViaVks(base: String, armored: String) {
        val url = "$base/vks/v1/upload"
        val payload = JSONObject().put("keytext", armored).toString()
        val conn = openConnection(url, method = "POST").apply {
            doOutput = true
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
            setRequestProperty("Accept", "application/json")
        }
        try {
            conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val body = readResponseBody(conn, code)
            if (code == 404 || code == 405) {
                throw PgpException("VKS not available (HTTP $code)")
            }
            if (code !in 200..299) {
                val msg = parseVksError(body) ?: body.take(200)
                throw PgpException("VKS upload HTTP $code${msg.takeIf { it.isNotBlank() }?.let { ": $it" } ?: ""}")
            }
            val json = runCatching { JSONObject(body) }.getOrNull()
            if (json?.has("error") == true) {
                throw PgpException(json.optString("error", "VKS upload rejected"))
            }
            // Success: key_fpr present, or token/status for pending email verification
            val hasFpr = json?.has("key_fpr") == true && json.optString("key_fpr").isNotBlank()
            val hasToken = json?.has("token") == true && json.optString("token").isNotBlank()
            val hasStatus = json?.has("status") == true
            if (!hasFpr && !hasToken && !hasStatus && body.isNotBlank() && !body.contains("ok", ignoreCase = true)) {
                // Empty 200 from some servers is OK; non-empty non-JSON without markers is suspicious
                if (json == null && body.length > 20) {
                    throw PgpException("VKS upload returned unexpected response")
                }
            }
        } finally {
            conn.disconnect()
        }
    }

    private fun uploadViaHkp(base: String, armored: String) {
        val url = "$base/pks/add"
        val body = "keytext=${URLEncoder.encode(armored, Charsets.UTF_8)}"
        val conn = openConnection(url, method = "POST").apply {
            doOutput = true
            setRequestProperty("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
            setRequestProperty("Accept", "text/html, text/plain, */*")
        }
        try {
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val response = readResponseBody(conn, code)
            if (code == 404 || code == 405) {
                throw PgpException("HKP add not available (HTTP $code)")
            }
            if (code !in 200..299) {
                throw PgpException("HKP upload HTTP $code${response.take(120).let { if (it.isBlank()) "" else ": $it" }}")
            }
            if (response.contains("error", ignoreCase = true) &&
                !response.contains("success", ignoreCase = true) &&
                !response.contains("stored", ignoreCase = true)
            ) {
                throw PgpException("Keyserver rejected upload: ${response.take(200)}")
            }
        } finally {
            conn.disconnect()
        }
    }

    private fun readArmoredKey(conn: HttpURLConnection): ByteArray {
        val code = conn.responseCode
        if (code !in 200..299) {
            val err = readResponseBody(conn, code).take(200)
            throw PgpException("Keyserver HTTP $code${err.takeIf { it.isNotBlank() }?.let { ": $it" } ?: ""}")
        }
        val stream = conn.inputStream ?: throw PgpException("Empty keyserver response")
        val out = ByteArrayOutputStream()
        PgpIo.copyLimited(stream, out, MAX_RESPONSE_BYTES.toLong())
        val body = out.toByteArray()
        if (body.isEmpty()) throw PgpException("No key found")
        if (!String(body, Charsets.UTF_8).contains("BEGIN PGP")) {
            throw PgpException("Keyserver returned no PGP key material")
        }
        return body
    }

    private fun openConnection(url: String, method: String): HttpURLConnection =
        (URI(url).toURL().openConnection() as HttpURLConnection).apply {
            connectTimeout = TIMEOUT_MS
            readTimeout = TIMEOUT_MS
            requestMethod = method
            instanceFollowRedirects = true
            setRequestProperty("User-Agent", USER_AGENT)
        }

    private fun readResponseBody(conn: HttpURLConnection, code: Int): String =
        (if (code in 200..299) conn.inputStream else conn.errorStream)
            ?.readBytes()
            ?.toString(Charsets.UTF_8)
            .orEmpty()

    private fun parseVksError(body: String): String? = runCatching {
        JSONObject(body).optString("error").takeIf { it.isNotBlank() }
    }.getOrNull()

    private fun looksLikeFingerprint(query: String): Boolean =
        FINGERPRINT_RE.matches(normalizeFingerprint(query.replace(" ", "")))

    private fun looksLikeKeyId(query: String): Boolean =
        runCatching { KEY_ID_RE.matches(normalizeKeyIdHex(query)) }.getOrDefault(false)

    /**
     * URL builders and key-id normalization helpers shared with tests and callers.
     */
    companion object {
        /** Default keyserver — Ubuntu HKP (index + get + add). VKS-only servers remain supported. */
        const val DEFAULT_URL = "https://keyserver.ubuntu.com"

        /** Privacy-oriented VKS fallback used after the primary when fetching by email/fingerprint. */
        const val VKS_FALLBACK_URL = "https://keys.openpgp.org"

        /** Additional HKP/VKS servers tried when the primary returns empty results. */
        val FALLBACK_HKP_URLS = listOf(
            "https://keys.openpgp.org",
            "https://keyserver.ubuntu.com",
            "https://keys.mailvelope.com",
            "https://pgpkeys.eu",
        )

        const val MAX_RESPONSE_BYTES = 512 * 1024
        private const val TIMEOUT_MS = 20_000
        private const val USER_AGENT = "PGP-Shield/1.0 (Android; OpenPGP keyserver client)"
        private val FINGERPRINT_RE = Regex("^[0-9A-F]{40}$")
        private val KEY_ID_RE = Regex("^[0-9A-F]{8,16}$")

        fun keyIdToHex(keyId: Long): String =
            keyId.toULong().toString(16).uppercase().padStart(16, '0').takeLast(16)

        fun normalizeFingerprint(raw: String): String =
            raw.filter { !it.isWhitespace() }.uppercase()

        fun normalizeKeyIdHex(raw: String): String {
            val trimmed = raw.trim()
            val withSign = when {
                trimmed.startsWith("0x", ignoreCase = true) -> trimmed.drop(2)
                else -> trimmed
            }
            if (withSign.startsWith('-')) {
                val signed = withSign.toLong(16)
                return keyIdToHex(signed)
            }
            val hex = withSign.filter { !it.isWhitespace() }.uppercase()
            require(hex.all { it in '0'..'9' || it in 'A'..'F' }) { "Invalid key id: $raw" }
            return hex.padStart(16, '0').takeLast(16)
        }

        fun candidateBases(preferred: String): List<String> {
            val primary = preferred.trim().trimEnd('/')
            val ordered = LinkedHashSet<String>()
            if (primary.isNotEmpty()) ordered += primary
            FALLBACK_HKP_URLS.forEach { ordered += it.trimEnd('/') }
            return ordered.toList()
        }

        /**
         * Ordered lookup URLs for [query] against [base].
         *
         * Email/fingerprint try VKS then HKP `op=get` (Ubuntu has no VKS but HKP get works).
         */
        fun lookupUrls(base: String, query: String): List<String> {
            val trimmed = query.trim()
            val root = base.trimEnd('/')
            val urls = LinkedHashSet<String>()
            when {
                trimmed.contains('@') -> {
                    val enc = URLEncoder.encode(trimmed, Charsets.UTF_8)
                    urls += "$root/vks/v1/by-email/$enc"
                    urls += "$root/pks/lookup?op=get&options=mr&search=$enc"
                }
                else -> {
                    val compact = trimmed.replace(" ", "")
                    val fp = normalizeFingerprint(compact)
                    if (FINGERPRINT_RE.matches(fp)) {
                        urls += "$root/vks/v1/by-fingerprint/$fp"
                        urls += "$root/pks/lookup?op=get&options=mr&search=0x$fp"
                    } else {
                        val keyId = runCatching { normalizeKeyIdHex(compact) }.getOrNull()
                        if (keyId != null && KEY_ID_RE.matches(keyId)) {
                            urls += "$root/pks/lookup?op=get&options=mr&search=0x$keyId"
                            urls += "$root/vks/v1/by-fingerprint/${keyId.padStart(40, '0')}"
                        } else {
                            val hkpSearch = URLEncoder.encode(compact, Charsets.UTF_8)
                            urls += "$root/pks/lookup?op=get&options=mr&search=$hkpSearch"
                        }
                    }
                }
            }
            return urls.toList()
        }

        /** First preferred lookup URL (kept for tests / simple callers). */
        fun buildLookupUrl(base: String, query: String): String =
            lookupUrls(base, query).first()
    }

    private fun lookupUrls(base: String, query: String): List<String> =
        Companion.lookupUrls(base, query)

    private fun candidateBases(preferred: String): List<String> =
        Companion.candidateBases(preferred)
}
