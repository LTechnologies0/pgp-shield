package ltechnologies.onionphone.pgpshield.ui.navigation

/**
 * Reversible encoding of 64-bit key ids for use in navigation route arguments.
 */

/** Encode OpenPGP key ids (often negative as [Long]) for navigation routes. */
object KeyNavIds {
    /** Encodes [keyId] as an unsigned hex string safe for a route segment. */
    fun encode(keyId: Long): String = keyId.toULong().toString(16)

    /** Decodes a hex route segment back into a [Long] key id (0 when invalid). */
    fun decode(hex: String?): Long = hex?.toULongOrNull(16)?.toLong() ?: 0L
}
