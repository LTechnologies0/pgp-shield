package ltechnologies.onionphone.pgpshield.util

/**
 * Parsing helpers for OpenPGP key identifiers supplied as text.
 */

/** Converts textual key identifiers (hex or decimal) into numeric key IDs. */
object KeyIdParser {
    /**
     * Parses a single key id from [value], accepting an optional `0x` prefix.
     *
     * Hexadecimal is attempted first, then decimal.
     *
     * @return the parsed key id, or `null` when [value] is empty or malformed.
     */
    fun parse(value: String): Long? {
        val trimmed = value.trim().removePrefix("0x").removePrefix("0X")
        if (trimmed.isEmpty()) return null
        return trimmed.toLongOrNull(16) ?: trimmed.toLongOrNull()
    }

    /** Parses a comma-separated list of key ids, skipping unparseable entries. */
    fun parseCsv(csv: String): List<Long> =
        csv.split(',').mapNotNull { parse(it) }
}
