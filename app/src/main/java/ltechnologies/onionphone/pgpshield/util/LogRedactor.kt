package ltechnologies.onionphone.pgpshield.util

/**
 * Central log scrubbing so that secrets never reach logcat or crash reports.
 */

import timber.log.Timber

/**
 * Detects and redacts sensitive substrings (passphrases, key material,
 * fingerprints) and provides a hardened [Timber.Tree] for release builds.
 */
object LogRedactor {
    private val secretPatterns = listOf(
        Regex("(?i)passphrase"),
        Regex("(?i)password"),
        Regex("(?i)secret.?key"),
        Regex("-----BEGIN PGP"),
        Regex("-----BEGIN [A-Z ]*PRIVATE KEY"),
        Regex("(?i)armored"),
        Regex("(?i)fingerprint"),
        Regex("[0-9A-Fa-f]{40}"),
    )

    /** Returns `true` when [message] matches any known secret pattern. */
    fun looksSensitive(message: String): Boolean =
        secretPatterns.any { it.containsMatchIn(message) }

    /** Replaces the whole message with `[REDACTED]` when it looks sensitive. */
    fun redact(message: String): String =
        if (looksSensitive(message)) "[REDACTED]" else message

    /**
     * Builds a [Timber.Tree] for release builds that logs only error-level
     * messages and redacts them before emitting to logcat.
     */
    fun createReleaseTree(): Timber.Tree = object : Timber.Tree() {
        override fun log(priority: Int, tag: String?, message: String, t: Throwable?) {
            // ponytail: release builds log errors only, redacted
            if (priority >= android.util.Log.ERROR) {
                android.util.Log.println(priority, tag, redact(message))
            }
        }
    }
}
