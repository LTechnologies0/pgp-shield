package ltechnologies.onionphone.pgpshield.intent

/**
 * Share / VIEW payloads are accepted only as `content://` URIs.
 *
 * `file://` and other schemes are rejected so the app never reads or deletes
 * caller-controlled filesystem paths.
 */
object ShareUriPolicy {
    fun isAllowedContentScheme(scheme: String?): Boolean =
        scheme.equals("content", ignoreCase = true)

    fun requireContentUri(uri: android.net.Uri): android.net.Uri {
        require(isAllowedContentScheme(uri.scheme)) {
            "Share payloads must be content:// URIs"
        }
        return uri
    }
}
