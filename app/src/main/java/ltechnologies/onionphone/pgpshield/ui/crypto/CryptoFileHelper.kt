package ltechnologies.onionphone.pgpshield.ui.crypto

/**
 * File-system and sharing utilities used by the crypto screen for file/folder payloads.
 */

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Helpers for persisting crypto results to the app cache and sharing them, plus
 * heuristics for deriving output file names from an input name.
 */
object CryptoFileHelper {
    /** Writes [data] to a cache file and launches a system share sheet for it. */
    suspend fun shareBytes(context: Context, data: ByteArray, fileName: String, mimeType: String) {
        val uri = writeCacheFile(context, data, fileName)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = mimeType
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(Intent.createChooser(send, "Share $fileName"))
    }

    /** Writes [data] into the shared cache directory and returns a content [Uri] for it. */
    suspend fun writeCacheFile(context: Context, data: ByteArray, fileName: String): Uri =
        withContext(Dispatchers.IO) {
            val dir = File(context.cacheDir, "shared").also { it.mkdirs() }
            val out = File(dir, fileName)
            out.writeBytes(data)
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", out)
        }

    /** Derives an encrypted output name for [inputName], appending `.gpg` when needed. */
    fun guessEncryptedName(inputName: String): String = when {
        inputName.endsWith(".gpg", ignoreCase = true) -> inputName
        inputName.endsWith(".pgp", ignoreCase = true) -> inputName
        inputName.contains('.') -> "${inputName.substringBeforeLast('.')}.gpg"
        else -> "$inputName.gpg"
    }

    /** Derives a decrypted output name by stripping a `.gpg`/`.pgp`/`.asc` suffix. */
    fun guessDecryptedName(inputName: String): String = when {
        inputName.endsWith(".gpg", ignoreCase = true) -> inputName.removeSuffix(".gpg")
        inputName.endsWith(".pgp", ignoreCase = true) -> inputName.removeSuffix(".pgp")
        inputName.endsWith(".asc", ignoreCase = true) -> inputName.removeSuffix(".asc")
        else -> inputName
    }

    /** Derives a detached signature name for [inputName], appending `.sig` when needed. */
    fun guessSignatureName(inputName: String): String = when {
        inputName.endsWith(".sig", ignoreCase = true) -> inputName
        inputName.contains('.') -> "${inputName.substringBeforeLast('.')}.sig"
        else -> "$inputName.sig"
    }
}
