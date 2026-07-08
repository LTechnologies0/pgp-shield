package ltechnologies.onionphone.pgpshield.util

/**
 * Privacy-safe logging: release builds emit only boolean flags (event=true/false).
 * Never log paths, key material, passphrases, or file contents.
 */

import android.util.Log
import ltechnologies.onionphone.pgpshield.BuildConfig

/** Release-safe logger that emits only boolean outcome flags. */
object PrivacyLog {
    private const val TAG = "OpPrivacy"

    /**
     * Logs a boolean outcome flag for [event] (sanitized) with no further detail.
     *
     * @param event Event name; non-alphanumeric characters are replaced.
     * @param ok Whether the event succeeded.
     */
    fun flag(event: String, ok: Boolean) {
        Log.i(TAG, sanitizeEvent(event) + "=" + if (ok) "true" else "false")
    }

    /**
     * Logs a boolean flag with extra [detail] in debug builds only; release
     * builds fall back to the detail-free [flag] to avoid leaking information.
     */
    fun flag(event: String, ok: Boolean, detail: String) {
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "${sanitizeEvent(event)}=$ok detail=$detail")
        } else {
            flag(event, ok)
        }
    }

    private fun sanitizeEvent(event: String): String =
        event.replace(Regex("[^a-zA-Z0-9._-]"), "_").take(64)
}
