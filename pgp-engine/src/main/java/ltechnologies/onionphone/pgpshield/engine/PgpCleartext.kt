package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP cleartext / text-signature canonicalization (RFC 4880 §7.1).
 *
 * Trailing whitespace is stripped per line and line endings between lines are
 * CRLF. Matching Bouncy Castle's `ClearSignedFileProcessor` and GnuPG, the
 * final line terminator is **not** included in the hash — hashing a trailing
 * `\r\n` after the last line produces signatures that verify in-app but fail
 * `gpg --verify` with "BAD signature".
 */
object PgpCleartext {
    /**
     * Canonicalizes UTF-8 cleartext for [PGPSignature.CANONICAL_TEXT_DOCUMENT].
     *
     * @return UTF-8 bytes hashed by cleartext / text signatures.
     */
    fun canonicalize(data: ByteArray): ByteArray =
        canonicalize(data.toString(Charsets.UTF_8))

    /** Canonicalizes a Unicode string the same way as [canonicalize]. */
    fun canonicalize(text: String): ByteArray {
        val normalized = text.replace("\r\n", "\n").replace("\r", "\n").trimEnd('\n')
        if (normalized.isEmpty()) {
            return ByteArray(0)
        }
        // Join with CRLF between lines only — no terminator after the last line.
        val body = normalized.split("\n").joinToString("\r\n") { it.trimEnd() }
        return body.toByteArray(Charsets.UTF_8)
    }

    /** LF form written into ASCII-armor cleartext sections (GnuPG style). */
    fun displayForm(hashedCanonical: ByteArray): ByteArray =
        hashedCanonical.toString(Charsets.UTF_8).replace("\r\n", "\n").toByteArray(Charsets.UTF_8)
}
