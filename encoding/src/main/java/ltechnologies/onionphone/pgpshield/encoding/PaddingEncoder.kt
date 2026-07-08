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
     * @return Payload after the template block, or `null` if the prefix does not match.
     */
    fun decode(encoded: String, templateTitle: String, templateBody: String): String? {
        val marker = "$templateTitle\n\n$templateBody\n\n"
        if (!encoded.startsWith(marker)) return null
        return encoded.removePrefix(marker)
    }
}
