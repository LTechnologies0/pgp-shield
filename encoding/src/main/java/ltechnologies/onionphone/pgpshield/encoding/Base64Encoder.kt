package ltechnologies.onionphone.pgpshield.encoding

import android.util.Base64

/**
 * Simple UTF-8 Base64 encoding for low-obfuscation overlay payloads.
 */
object Base64Encoder {
    /** Encodes [plaintext] as standard Base64 without line wraps. */
    fun encode(plaintext: String): String =
        Base64.encodeToString(plaintext.toByteArray(Charsets.UTF_8), Base64.NO_WRAP)

    /**
     * Decodes [encoded] Base64 to UTF-8 text.
     *
     * @return Decoded string, or `null` on invalid Base64.
     */
    fun decode(encoded: String): String? = runCatching {
        String(Base64.decode(encoded.trim(), Base64.NO_WRAP), Charsets.UTF_8)
    }.getOrNull()
}
