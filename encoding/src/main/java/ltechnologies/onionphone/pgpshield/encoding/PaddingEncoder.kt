package ltechnologies.onionphone.pgpshield.encoding

/**
 * Template-based steganography: hides plaintext after a recognizable cover block.
 *
 * The encoded form is `title`, blank line, template body, blank line, then secret payload.
 * Decoding succeeds only when the input starts with the exact marker derived from the template.
 */
class PaddingEncoder {
    /**
     * Wraps [plaintext] after [templateTitle] and [templateBody] with standard paragraph spacing.
     */
    fun encode(plaintext: String, templateTitle: String, templateBody: String): String =
        "$templateTitle\n\n$templateBody\n\n$plaintext"

    /**
     * Extracts hidden plaintext from [encoded] if it matches the template marker.
     *
     * Newlines are normalized to LF before matching so messenger CRLF rewriting
     * does not break decode.
     *
     * @return Payload after the template block, or `null` if the prefix does not match.
     */
    fun decode(encoded: String, templateTitle: String, templateBody: String): String? {
        val normalized = normalizeNewlines(encoded)
        val marker = normalizeNewlines("$templateTitle\n\n$templateBody\n\n")
        if (!normalized.startsWith(marker)) return null
        return normalized.removePrefix(marker)
    }

    private fun normalizeNewlines(text: String): String =
        text.replace("\r\n", "\n").replace("\r", "\n")
}
