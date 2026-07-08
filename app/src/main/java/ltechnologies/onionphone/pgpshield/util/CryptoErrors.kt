package ltechnologies.onionphone.pgpshield.util

/**
 * Helpers for turning cryptographic exceptions into safe, user-facing text.
 */

/** Sanitizes exception messages so that sensitive data is never surfaced. */
object CryptoErrors {
    /**
     * Returns a short, non-sensitive message derived from [e], falling back to
     * [fallback] when the message is empty or looks like it could leak secrets.
     *
     * @param e The throwable whose message is being considered.
     * @param fallback Generic message used when the raw message is unsafe.
     */
    fun safeMessage(e: Throwable, fallback: String): String {
        val raw = e.message?.trim().orEmpty()
        if (raw.isEmpty() || LogRedactor.looksSensitive(raw)) return fallback
        return raw.take(200)
    }
}
