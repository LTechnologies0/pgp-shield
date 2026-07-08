package ltechnologies.onionphone.pgpshield.intent

/**
 * Extracts text and binary payloads from incoming intents across the various
 * ways senders can attach data (extras, `ACTION_PROCESS_TEXT`, data URI,
 * `EXTRA_STREAM`, clip data).
 */

import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.activity.ComponentActivity
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import ltechnologies.onionphone.pgpshield.util.DebugAgentLog
import timber.log.Timber

/** Resolves and reads intent payloads, preferring extras then URIs. */
object IntentPayloadReader {
    /**
     * Returns text from the intent, checking `EXTRA_TEXT`, the app's text extra,
     * `ACTION_PROCESS_TEXT` and finally a text-like data URI, or `null`.
     */
    fun readText(intent: Intent, activity: ComponentActivity? = null): String? {
        intent.getStringExtra(Intent.EXTRA_TEXT)?.takeIf { it.isNotBlank() }?.let { return it }
        intent.getStringExtra(PgpIntentActions.EXTRA_TEXT)?.takeIf { it.isNotBlank() }?.let { return it }
        if (Intent.ACTION_PROCESS_TEXT == intent.action) {
            intent.getCharSequenceExtra(Intent.EXTRA_PROCESS_TEXT)?.toString()
                ?.takeIf { it.isNotBlank() }?.let { return it }
        }
        val uri = intent.data
        if (uri != null && activity != null && (intent.type?.startsWith("text/") == true || looksLikeTextUri(uri))) {
            return try {
                activity.contentResolver.openInputStream(uri)?.use { stream ->
                    String(PgpIo.readLimited(stream, maxBytes = 512 * 1024), Charsets.UTF_8)
                }
            } catch (e: Exception) {
                Timber.e(e, "Intent text read failed")
                null
            }
        }
        return null
    }

    /**
     * Resolves the payload URI from the intent and reads it (size-limited),
     * returning the bytes or `null` when no readable payload is present.
     */
    fun readBytes(intent: Intent, activity: ComponentActivity): ByteArray? {
        val uri = resolvePayloadUri(intent) ?: run {
            // #region agent log
            DebugAgentLog.log(
                location = "IntentPayloadReader.kt:readBytes",
                message = "no payload URI in intent",
                data = mapOf(
                    "action" to intent.action,
                    "hasData" to (intent.data != null),
                    "hasClipData" to (intent.clipData != null),
                    "hasExtraStream" to intent.hasExtra(Intent.EXTRA_STREAM),
                ),
                hypothesisId = "B",
            )
            // #endregion
            return null
        }
        return try {
            val bytes = activity.contentResolver.openInputStream(uri)?.use { PgpIo.readLimited(it) }
            // #region agent log
            DebugAgentLog.log(
                location = "IntentPayloadReader.kt:readBytes",
                message = "payload read",
                data = mapOf(
                    "uri" to uri.toString(),
                    "byteCount" to (bytes?.size ?: 0),
                ),
                hypothesisId = "B",
            )
            // #endregion
            bytes
        } catch (e: Exception) {
            Timber.e(e, "Intent bytes read failed")
            // #region agent log
            DebugAgentLog.log(
                location = "IntentPayloadReader.kt:readBytes",
                message = "payload read failed",
                data = mapOf("uri" to uri.toString(), "error" to (e.message ?: e.javaClass.simpleName)),
                hypothesisId = "B",
            )
            // #endregion
            null
        }
    }

    private fun resolvePayloadUri(intent: Intent): Uri? {
        intent.data?.let { return it }
        intentStreamUri(intent)?.let { return it }
        return intent.clipData?.takeIf { it.itemCount > 0 }?.getItemAt(0)?.uri
    }

    @Suppress("DEPRECATION")
    private fun intentStreamUri(intent: Intent): Uri? {
        if (!intent.hasExtra(Intent.EXTRA_STREAM)) return null
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
                ?.firstOrNull()?.let { return it }
        }
        @Suppress("UNCHECKED_CAST")
        (intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM))?.firstOrNull()?.let { return it }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)?.let { return it }
        }
        return intent.getParcelableExtra(Intent.EXTRA_STREAM)
    }

    private fun looksLikeTextUri(uri: Uri): Boolean {
        val path = uri.lastPathSegment?.lowercase() ?: return false
        return path.endsWith(".asc") || path.endsWith(".txt") || path.endsWith(".gpg")
    }
}
