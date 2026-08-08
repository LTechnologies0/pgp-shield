package ltechnologies.onionphone.pgpshield.data.security

import java.io.File
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

/**
 * File-backed AES-GCM blobs sealed with a [StrongBoxAesKeyFactory] key (no per-op user auth).
 *
 * Format: magic(3) + version(1) + iv(12) + ciphertext+tag.
 */
class StrongBoxSealedBlobStore(
    private val dir: File,
    private val keyAlias: String,
    private val context: android.content.Context,
    private val magic0: Byte,
    private val magic1: Byte,
    private val magic2: Byte,
) {
    init {
        dir.mkdirs()
    }

    fun ensureKey(): StrongBoxAesKeyFactory.KeyHandle =
        StrongBoxAesKeyFactory.getOrCreate(
            context = context,
            alias = keyAlias,
            userAuthenticationRequired = false,
            requireInsideSecureHardware = true,
        )

    fun seal(name: String, plaintext: ByteArray) {
        val handle = ensureKey()
        val cipher = Cipher.getInstance(StrongBoxAesKeyFactory.transformation())
        cipher.init(Cipher.ENCRYPT_MODE, handle.key)
        val iv = cipher.iv
        require(iv.size == IV_LEN)
        val ciphertext = cipher.doFinal(plaintext)
        val out = ByteArray(HEADER_LEN + IV_LEN + ciphertext.size)
        out[0] = magic0
        out[1] = magic1
        out[2] = magic2
        out[3] = VERSION
        System.arraycopy(iv, 0, out, HEADER_LEN, IV_LEN)
        System.arraycopy(ciphertext, 0, out, HEADER_LEN + IV_LEN, ciphertext.size)
        File(dir, name).writeBytes(out)
        SensitiveMemory.wipe(out, ciphertext)
    }

    fun unseal(name: String): ByteArray? {
        val file = File(dir, name)
        if (!file.isFile) return null
        val blob = file.readBytes()
        require(blob.size > HEADER_LEN + IV_LEN) { "Corrupt sealed blob $name" }
        require(
            blob[0] == magic0 && blob[1] == magic1 &&
                blob[2] == magic2 && blob[3] == VERSION,
        ) { "Invalid sealed blob magic $name" }
        val handle = ensureKey()
        val iv = blob.copyOfRange(HEADER_LEN, HEADER_LEN + IV_LEN)
        val ciphertext = blob.copyOfRange(HEADER_LEN + IV_LEN, blob.size)
        return try {
            val cipher = Cipher.getInstance(StrongBoxAesKeyFactory.transformation())
            cipher.init(Cipher.DECRYPT_MODE, handle.key, GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.doFinal(ciphertext)
        } finally {
            SensitiveMemory.wipe(blob, iv, ciphertext)
        }
    }

    fun delete(name: String) {
        val f = File(dir, name)
        if (f.isFile) {
            runCatching {
                val len = f.length().toInt().coerceAtMost(256 * 1024)
                if (len > 0) f.writeBytes(ByteArray(len))
            }
            f.delete()
        }
    }

    fun exists(name: String): Boolean = File(dir, name).isFile

    companion object {
        private const val IV_LEN = 12
        private const val GCM_TAG_BITS = 128
        private const val HEADER_LEN = 4
        private const val VERSION: Byte = 1
    }
}
