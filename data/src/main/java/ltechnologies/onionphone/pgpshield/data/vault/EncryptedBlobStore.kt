package ltechnologies.onionphone.pgpshield.data.vault

import android.content.Context
import androidx.security.crypto.EncryptedFile
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import java.io.File
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Encrypted on-disk storage for armored PGP key ring blobs.
 *
 * Uses AndroidX [EncryptedFile] with AES-256-GCM and a hardware-backed [MasterKey].
 * Secret and public key material are stored as separate files under the app's private
 * `keyrings` directory. Deletion overwrites the leading ciphertext bytes before unlinking
 * as a defense-in-depth measure alongside full-disk encryption.
 */
@Singleton
class EncryptedBlobStore @Inject constructor(
    @ApplicationContext private val context: Context,
) : KeyBlobStore {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val dir: File by lazy {
        File(context.filesDir, "keyrings").also { it.mkdirs() }
    }

    /**
     * Writes secret key ring bytes for [keyId], replacing any existing file at the target path.
     *
     * @param keyId Master key identifier used to derive the filename.
     * @param data Armored secret key ring bytes.
     * @return Absolute filesystem path of the written encrypted file.
     */
    override fun write(keyId: Long, data: ByteArray): String = write(keyId, data, suffix = "")

    /**
     * Writes public key ring bytes for [keyId], stored separately from the secret blob.
     *
     * @param keyId Master key identifier used to derive the filename.
     * @param data Armored public key ring bytes.
     * @return Absolute filesystem path of the written encrypted file.
     */
    override fun writePublic(keyId: Long, data: ByteArray): String = write(keyId, data, suffix = "_pub")

    private fun write(keyId: Long, data: ByteArray, suffix: String): String {
        val path = fileFor(keyId, suffix)
        if (path.exists()) {
            delete(path.absolutePath)
        }
        EncryptedFile.Builder(
            context,
            path,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build().openFileOutput().use { it.write(data) }
        return path.absolutePath
    }

    /**
     * Reads and decrypts key ring bytes from [path].
     *
     * @param path Absolute path previously returned by [write] or [writePublic].
     * @return Decrypted armored key ring bytes, size-limited via [PgpIo.readLimited].
     * @throws java.io.FileNotFoundException if [path] does not refer to an existing file.
     */
    override fun read(path: String): ByteArray {
        val file = File(path)
        if (!file.isFile) {
            throw java.io.FileNotFoundException("file doesn't exist: ${file.name}")
        }
        return EncryptedFile.Builder(
            context,
            file,
            masterKey,
            EncryptedFile.FileEncryptionScheme.AES256_GCM_HKDF_4KB,
        ).build().openFileInput().use { PgpIo.readLimited(it) }
    }

    /**
     * Securely removes the encrypted file at [path].
     *
     * Overwrites up to the first 4 KiB of ciphertext before deletion. No-op if the file
     * does not exist.
     */
    override fun delete(path: String) {
        val file = File(path)
        if (!file.exists()) return
        // ponytail: overwrite ciphertext header before unlink; FBE still primary defense
        runCatching {
            val len = file.length().coerceAtMost(4096L).toInt()
            if (len > 0) {
                java.io.RandomAccessFile(file, "rw").use { raf ->
                    raf.seek(0)
                    raf.write(ByteArray(len))
                }
            }
        }
        file.delete()
    }

    private fun fileFor(keyId: Long, suffix: String = ""): File = File(dir, "kr_$keyId$suffix.gpg")
}
