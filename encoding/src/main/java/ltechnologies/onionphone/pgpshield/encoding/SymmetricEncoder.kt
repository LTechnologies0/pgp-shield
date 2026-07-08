package ltechnologies.onionphone.pgpshield.encoding

import android.util.Base64
import ltechnologies.onionphone.pgpshield.engine.SymmetricCipher
import ltechnologies.onionphone.pgpshield.engine.SymmetricDecryptRequest
import ltechnologies.onionphone.pgpshield.engine.SymmetricEncryptRequest

/**
 * Password-based symmetric encryption encoder for overlay and clipboard hiding.
 *
 * Plaintext is encrypted with [SymmetricCipher] and represented as standard Base64
 * (no line wraps) for embedding in visible text fields.
 */
class SymmetricEncoder(
    private val cipher: SymmetricCipher = SymmetricCipher(),
) {
    /**
     * Encrypts [plaintext] with [password] and returns Base64 ciphertext.
     */
    fun encode(plaintext: String, password: CharArray): String {
        val ct = cipher.encrypt(
            SymmetricEncryptRequest(plaintext.toByteArray(Charsets.UTF_8), password),
        )
        return Base64.encodeToString(ct, Base64.NO_WRAP)
    }

    /**
     * Decodes and decrypts [encoded] with [password].
     *
     * @return Decrypted UTF-8 plaintext, or `null` on decode/decrypt failure.
     */
    fun decode(encoded: String, password: CharArray): String? = runCatching {
        val ct = Base64.decode(encoded.trim(), Base64.NO_WRAP)
        val plain = cipher.decrypt(SymmetricDecryptRequest(ct, password))
        String(plain, Charsets.UTF_8)
    }.getOrNull()
}
