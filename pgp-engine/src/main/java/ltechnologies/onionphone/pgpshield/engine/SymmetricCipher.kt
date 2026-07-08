package ltechnologies.onionphone.pgpshield.engine

/**
 * Password-based symmetric encryption for non-OpenPGP payloads.
 *
 * Implements AES-256-GCM with PBKDF2-HMAC-SHA256 key derivation for Oversec-style
 * symmetric encryption outside the OpenPGP message format.
 */

import java.nio.ByteBuffer
import java.security.spec.KeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/** Plaintext and password for symmetric encryption. */
data class SymmetricEncryptRequest(
    val plaintext: ByteArray,
    val password: CharArray,
)

/** Ciphertext blob and password for symmetric decryption. */
data class SymmetricDecryptRequest(
    val ciphertext: ByteArray,
    val password: CharArray,
)

/**
 * AES-256-GCM cipher with PBKDF2-HMAC-SHA256 key derivation.
 *
 * Output format: magic (`OS1\0`) || salt (16) || IV (12) || ciphertext + GCM tag.
 */
class SymmetricCipher {
    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Encrypts [request.plaintext] with [request.password].
     *
     * @return Binary blob containing magic header, salt, IV, and authenticated ciphertext.
     */
    fun encrypt(request: SymmetricEncryptRequest): ByteArray {
        val salt = SecureRandomProvider.secureRandom.generateSeed(SALT_LEN)
        val iv = SecureRandomProvider.secureRandom.generateSeed(IV_LEN)
        val key = deriveKey(request.password, salt)
        val cipher = Cipher.getInstance(CIPHER)
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        val encrypted = cipher.doFinal(request.plaintext)
        return ByteBuffer.allocate(MAGIC.size + SALT_LEN + IV_LEN + encrypted.size)
            .put(MAGIC)
            .put(salt)
            .put(iv)
            .put(encrypted)
            .array()
    }

    /**
     * Decrypts a blob produced by [encrypt].
     *
     * @throws IllegalArgumentException if magic header is invalid or data is truncated.
     */
    fun decrypt(request: SymmetricDecryptRequest): ByteArray {
        val buf = ByteBuffer.wrap(request.ciphertext)
        val magic = ByteArray(MAGIC.size)
        buf.get(magic)
        require(magic.contentEquals(MAGIC)) { "Invalid symmetric ciphertext magic" }
        require(buf.remaining() >= SALT_LEN + IV_LEN + GCM_TAG_LEN) { "Ciphertext too short" }
        val salt = ByteArray(SALT_LEN)
        buf.get(salt)
        val iv = ByteArray(IV_LEN)
        buf.get(iv)
        val encrypted = ByteArray(buf.remaining())
        buf.get(encrypted)
        val key = deriveKey(request.password, salt)
        val cipher = Cipher.getInstance(CIPHER)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(encrypted)
    }

    /** Derives a 256-bit AES key from [password] and [salt] via PBKDF2-HMAC-SHA256. */
    private fun deriveKey(password: CharArray, salt: ByteArray): SecretKeySpec {
        val spec: KeySpec = PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_BITS)
        val factory = SecretKeyFactory.getInstance(PBKDF2)
        val raw = factory.generateSecret(spec).encoded
        return SecretKeySpec(raw, "AES")
    }

    companion object {
        private val MAGIC = byteArrayOf('O'.code.toByte(), 'S'.code.toByte(), '1'.code.toByte(), 0)
        private const val SALT_LEN = 16
        private const val IV_LEN = 12
        private const val GCM_TAG_BITS = 128
        private const val GCM_TAG_LEN = 16
        private const val KEY_BITS = 256
        private const val PBKDF2_ITERATIONS = 100_000
        private const val PBKDF2 = "PBKDF2WithHmacSHA256"
        private const val CIPHER = "AES/GCM/NoPadding"

        /** Round-trip encrypt/decrypt self-check; returns `false` on any failure. */
        fun selfCheck(): Boolean = runCatching {
            val pw = "test".toCharArray()
            val plain = "ok".toByteArray()
            val cipher = SymmetricCipher()
            val ct = cipher.encrypt(SymmetricEncryptRequest(plain, pw))
            val back = cipher.decrypt(SymmetricDecryptRequest(ct, pw))
            back.contentEquals(plain)
        }.getOrDefault(false)
    }
}
