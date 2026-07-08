package ltechnologies.onionphone.pgpshield.encoding

/**
 * Supported overlay encoding methods and stable string identifiers for persistence.
 */

/** Discriminator for which encoder handles overlay hide/reveal for a given app. */
enum class EncodingMethod {
    /** OpenPGP encryption (armored ciphertext). */
    GPG,

    /** Zero-width Unicode steganography ([ZeroWidthEncoder]). */
    ZERO_WIDTH,

    /** Template padding steganography ([PaddingEncoder]). */
    PADDING,

    /** Password-based symmetric encryption ([SymmetricEncoder]). */
    SYMMETRIC,

    /** Plain Base64 of UTF-8 bytes ([Base64Encoder]). */
    BASE64,
}

/** Maps between persisted encoding ids and [EncodingMethod] values. */
object EncodingRegistry {
    /**
     * Parses a stored or user-facing encoding id to [EncodingMethod].
     *
     * Unknown ids default to [EncodingMethod.GPG].
     */
    fun parseId(id: String): EncodingMethod = when (id.lowercase()) {
        "gpg" -> EncodingMethod.GPG
        "zwidth", "zero_width", "zerowidth" -> EncodingMethod.ZERO_WIDTH
        "padding", "pad" -> EncodingMethod.PADDING
        "symmetric", "sym" -> EncodingMethod.SYMMETRIC
        "base64", "b64" -> EncodingMethod.BASE64
        else -> EncodingMethod.GPG
    }

    /** Returns the canonical persisted id for [method]. */
    fun toId(method: EncodingMethod): String = when (method) {
        EncodingMethod.GPG -> "gpg"
        EncodingMethod.ZERO_WIDTH -> "zwidth"
        EncodingMethod.PADDING -> "padding"
        EncodingMethod.SYMMETRIC -> "symmetric"
        EncodingMethod.BASE64 -> "base64"
    }
}
