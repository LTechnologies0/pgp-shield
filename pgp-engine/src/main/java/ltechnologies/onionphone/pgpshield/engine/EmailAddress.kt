package ltechnologies.onionphone.pgpshield.engine

/**
 * Exact OpenPGP user-id email extraction (no substring / wildcard matching).
 */
object EmailAddress {
    private val ANGLE = Regex("^.*<([^>]+@[^>]+)>$")

    /**
     * Normalizes [raw] to a lowercase email, or `null` when it is not an address.
     *
     * Accepts `user@host` or `Name <user@host>`. Rejects blank and wildcard-only input.
     */
    fun normalize(raw: String?): String? {
        val trimmed = raw?.trim().orEmpty()
        if (trimmed.isEmpty()) return null
        val extracted = extract(trimmed) ?: return null
        if (extracted.contains('%') || extracted.contains('*')) return null
        return extracted
    }

    /** Email from a user-id string, or `null` when no address is present. */
    fun extract(userId: String): String? {
        val trimmed = userId.trim()
        if (trimmed.isEmpty()) return null
        ANGLE.matchEntire(trimmed)?.groupValues?.getOrNull(1)?.let { inner ->
            return inner.trim().lowercase()
        }
        return if (trimmed.contains('@') && !trimmed.contains(' ')) {
            trimmed.lowercase()
        } else {
            null
        }
    }

    /** True when [userId] carries exactly [email] (case-insensitive). */
    fun userIdMatchesEmail(userId: String, email: String): Boolean {
        val wanted = normalize(email) ?: return false
        return extract(userId) == wanted
    }
}
