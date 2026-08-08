package ltechnologies.onionphone.pgpshield.intent

/**
 * Suspending I/O helpers for reading intent payloads and resolving keys.
 */

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.activity.ComponentActivity
import androidx.core.content.FileProvider
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import java.io.File
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import timber.log.Timber

/** Off-main-thread helpers that back the Intent activities. */
object IntentIoHelper {
    /** Reads text from the intent on [Dispatchers.IO]; see [IntentPayloadReader.readText]. */
    suspend fun readText(intent: Intent, activity: ComponentActivity): String? =
        withContext(Dispatchers.IO) { IntentPayloadReader.readText(intent, activity) }

    /** Reads binary payload bytes from the intent on [Dispatchers.IO]. */
    suspend fun readBytes(intent: Intent, activity: ComponentActivity): ByteArray? =
        withContext(Dispatchers.IO) { IntentPayloadReader.readBytes(intent, activity) }

    /**
     * Reads all bytes from [uri] (size-limited).
     *
     * @throws IllegalStateException when the URI cannot be opened.
     */
    suspend fun readUriBytes(context: Context, uri: Uri): ByteArray =
        withContext(Dispatchers.IO) {
            context.contentResolver.openInputStream(uri)?.use { PgpIo.readLimited(it) }
                ?: throw IllegalStateException("Cannot open $uri")
        }

    /** Reads [uri] returning its display name paired with its bytes, or `null` on failure. */
    suspend fun readUriNamed(context: Context, uri: Uri): Pair<String, ByteArray>? =
        withContext(Dispatchers.IO) {
            try {
                val name = uri.lastPathSegment?.substringAfterLast('/') ?: "file.bin"
                val bytes = context.contentResolver.openInputStream(uri)?.use { PgpIo.readLimited(it) }
                    ?: return@withContext null
                name to bytes
            } catch (e: Exception) {
                Timber.e(e, "Failed to read intent URI")
                null
            }
        }

    /**
     * Resolves the recipient public key to encrypt to (default encrypt key, then
     * first allowed key). Skips Never-trusted, revoked, expired, or policy-rejected rings.
     *
     * @throws IllegalStateException when no allowed recipient key is configured.
     */
    suspend fun loadEncryptPublicKey(
        keyRepository: KeyRepository,
        settingsRepository: SettingsRepository,
    ): ByteArray = withContext(Dispatchers.IO) {
        val settings = settingsRepository.current()
        val keys = keyRepository.observeKeys().first()
        val candidates = buildList {
            settings.defaultEncryptKeyId?.let { add(it) }
            keys.forEach { add(it.masterKeyId) }
        }.distinct()
        for (id in candidates) {
            if (!keyRepository.isEncryptRecipientAllowed(id)) continue
            keyRepository.getArmoredPublic(id)?.let { return@withContext it }
        }
        error("No allowed recipient key — Never-trusted, revoked, or expired keys are skipped")
    }

    /**
     * Resolves the secret key used for decryption (default sign key or the first
     * available secret key).
     *
     * @throws IllegalStateException when no secret key is present.
     */
    suspend fun loadDecryptSecretKey(
        keyRepository: KeyRepository,
        settingsRepository: SettingsRepository,
    ): ByteArray = withContext(Dispatchers.IO) {
        val settings = settingsRepository.current()
        val keys = keyRepository.observeKeys().first()
        val keyId = settings.defaultSignKeyId
            ?: keys.firstOrNull { it.isSecret }?.masterKeyId
            ?: error("No secret key on device")
        keyRepository.getArmoredSecret(keyId)
            ?: error("Secret key material missing")
    }

    /**
     * Writes [data] into the app's shared cache directory and returns a
     * `FileProvider` URI suitable for sharing to other apps.
     */
    suspend fun writeShareFile(context: Context, data: ByteArray, name: String): Uri =
        withContext(Dispatchers.IO) {
            val dir = File(context.cacheDir, "shared").also { it.mkdirs() }
            val out = File(dir, name)
            out.writeBytes(data)
            FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", out)
        }
}
