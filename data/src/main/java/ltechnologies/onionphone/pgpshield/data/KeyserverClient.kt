package ltechnologies.onionphone.pgpshield.data

import ltechnologies.onionphone.pgpshield.engine.PgpException
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import javax.inject.Inject
import javax.inject.Singleton
import org.json.JSONObject

/**
 * HTTP client for OpenPGP keyserver lookup and upload.
 *
 * Supports VKS (keys.openpgp.org style) endpoints for fetch and upload, with HKP fallback
 * when VKS is unavailable. Lookup accepts email addresses, fingerprints, and key ids.
 */
@Singleton
class KeyserverClient @Inject constructor() {
    /**
     * Fetches an armored public key from [baseUrl] matching [query].
     *
     * @param baseUrl Keyserver base URL (e.g. `https://keys.openpgp.org`).
     * @param query Email address, 40-hex fingerprint, or 8–16 hex key id.
     * @return Armored PGP public key bytes.
     * @throws PgpException on HTTP errors, empty responses, or non-PGP payloads.
     * @throws IllegalArgumentException if [query] is blank.
     */
    fun fetchKey(baseUrl: String, query: String): ByteArray {
        val trimmed = query.trim()
        require(trimmed.isNotEmpty()) { "Empty search query" }
        val url = buildLookupUrl(baseUrl.trimEnd('/'), trimmed)
        val conn = openConnection(url, method = "GET").apply {
            setRequestProperty("Accept", "application/pgp-keys, application/octet-stream, */*")
        }
        try {
            return readArmoredKey(conn)
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Uploads armored public key material to [baseUrl].
     *
     * Attempts VKS JSON upload first (`/vks/v1/upload`); falls back to HKP `/pks/add`
     * when VKS is unavailable or rejects the request.
     *
     * @param baseUrl Keyserver base URL.
     * @param armoredPublic UTF-8 armored public key block.
     * @throws PgpException if both VKS and HKP upload fail.
     * @throws IllegalArgumentException if [armoredPublic] is not armored public key material.
     */
    fun uploadPublicKey(baseUrl: String, armoredPublic: ByteArray) {
        val armored = String(armoredPublic, Charsets.UTF_8).trim()
        require(armored.contains("BEGIN PGP PUBLIC")) { "Not armored public key material" }
        val base = baseUrl.trimEnd('/')
        runCatching { uploadViaVks(base, armored) }
            .onSuccess { return }
            .onFailure { vksError ->
                runCatching { uploadViaHkp(base, armored) }
                    .onSuccess { return }
                    .onFailure { hkpError ->
                        throw PgpException(
                            "Keyserver upload failed (VKS: ${vksError.message}; HKP: ${hkpError.message})",
                        )
                    }
            }
    }

    private fun uploadViaVks(base: String, armored: String) {
        val url = "$base/vks/v1/upload"
        val payload = JSONObject().put("keytext", armored).toString()
        val conn = openConnection(url, method = "POST").apply {
            doOutput = true
            setRequestProperty("Content-Type", "application/json; charset=utf-8")
        }
        try {
            conn.outputStream.use { it.write(payload.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val body = readResponseBody(conn, code)
            if (code !in 200..299) {
                val msg = parseVksError(body) ?: body.take(200)
                throw PgpException("VKS upload HTTP $code${msg.takeIf { it.isNotBlank() }?.let { ": $it" } ?: ""}")
            }
            val json = runCatching { JSONObject(body) }.getOrNull()
            if (json?.has("error") == true) {
                throw PgpException(json.optString("error", "VKS upload rejected"))
            }
            if (json?.has("key_fpr") != true) {
                throw PgpException("VKS upload returned unexpected response")
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
        }
        try {
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val response = readResponseBody(conn, code)
            if (code !in 200..299) {
                throw PgpException("HKP upload HTTP $code${response.take(120).let { if (it.isBlank()) "" else ": $it" }}")
            }
            if (response.contains("error", ignoreCase = true) && !response.contains("success", ignoreCase = true)) {
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
        }

    private fun readResponseBody(conn: HttpURLConnection, code: Int): String =
        (if (code in 200..299) conn.inputStream else conn.errorStream)
            ?.readBytes()
            ?.toString(Charsets.UTF_8)
            .orEmpty()

    private fun parseVksError(body: String): String? = runCatching {
        JSONObject(body).optString("error").takeIf { it.isNotBlank() }
    }.getOrNull()

    /**
     * URL builders and key-id normalization helpers shared with tests and callers.
     */
    internal companion object {
        /** Default keyserver base URL (keys.openpgp.org). */
        const val DEFAULT_URL = "https://keys.openpgp.org"

        /** Maximum HTTP response body size when fetching keys (512 KiB). */
        const val MAX_RESPONSE_BYTES = 512 * 1024
        private const val TIMEOUT_MS = 15_000
        private val FINGERPRINT_RE = Regex("^[0-9A-F]{40}$")
        private val KEY_ID_RE = Regex("^[0-9A-F]{8,16}$")

        /**
         * Converts a signed 64-bit [keyId] to uppercase 16-hex OpenPGP key id form.
         *
         * OpenPGP key ids are unsigned 64-bit; Java [Long] may be negative.
         */
        fun keyIdToHex(keyId: Long): String =
            keyId.toULong().toString(16).uppercase().padStart(16, '0').takeLast(16)

        /** Strips whitespace and uppercases a fingerprint string. */
        fun normalizeFingerprint(raw: String): String =
            raw.filter { !it.isWhitespace() }.uppercase()

        /**
         * Normalizes user input to a 16-hex key id, accepting `0x` prefix and signed hex.
         *
         * @throws IllegalArgumentException if the input contains invalid hex characters.
         */
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

        /**
         * Builds a VKS or HKP lookup URL for [query] against [base].
         *
         * Email queries use VKS by-email; 40-hex fingerprints and key ids use VKS endpoints;
         * other queries fall back to HKP `op=get`.
         */
        fun buildLookupUrl(base: String, query: String): String {
            val trimmed = query.trim()
            return when {
                trimmed.contains('@') ->
                    "$base/vks/v1/by-email/${URLEncoder.encode(trimmed, Charsets.UTF_8)}"
                else -> {
                    val compact = trimmed.replace(" ", "")
                    val fp = normalizeFingerprint(compact)
                    if (FINGERPRINT_RE.matches(fp)) {
                        return "$base/vks/v1/by-fingerprint/$fp"
                    }
                    val keyId = runCatching { normalizeKeyIdHex(compact) }.getOrNull()
                    if (keyId != null && KEY_ID_RE.matches(keyId)) {
                        return "$base/vks/v1/by-keyid/$keyId"
                    }
                    val hkpSearch = if (compact.contains('@')) {
                        URLEncoder.encode(trimmed, Charsets.UTF_8)
                    } else {
                        URLEncoder.encode(
                            runCatching { normalizeKeyIdHex(compact) }.getOrDefault(compact.uppercase()),
                            Charsets.UTF_8,
                        )
                    }
                    "$base/pks/lookup?op=get&options=mr&search=$hkpSearch"
                }
            }
        }
    }

    private fun buildLookupUrl(base: String, query: String): String =
        Companion.buildLookupUrl(base, query)
}
