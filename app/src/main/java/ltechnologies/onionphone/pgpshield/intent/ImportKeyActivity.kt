package ltechnologies.onionphone.pgpshield.intent

/**
 * Intent-launched screen for importing an OpenPGP key from a file, bytes, or keyserver.
 */

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dagger.hilt.android.AndroidEntryPoint
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.ImportGuard
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeyserverClient
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.util.ArmoredKeyDetector
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Handles incoming key-import intents (OpenKeychain-compatible import actions).
 *
 * Reads key bytes from an extra, `EXTRA_STREAM` or the data URI, or fetches from the
 * configured keyserver for [ACTION_IMPORT_KEY_FROM_KEYSERVER] / `openpgp4fpr:` URIs.
 * Enforces a size guard, auto-detects secret vs. public material and imports it.
 */
@AndroidEntryPoint
class ImportKeyActivity : LockedIntentActivity() {
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var settingsRepository: SettingsRepository
    @Inject lateinit var keyserverClient: KeyserverClient

    /** Builds the import UI and wires up the import action. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val label = intentKeyserverQuery()
            ?: intent.data?.lastPathSegment
            ?: getString(R.string.intent_default_key)
        setVaultGatedContent(settingsRepository) {
                var status by remember { mutableStateOf(getString(R.string.intent_import_key_status_fmt, label)) }
                var error by remember { mutableStateOf<String?>(null) }
                var busy by remember { mutableStateOf(false) }
                val scope = rememberCoroutineScope()

                IntentFlowScaffold(
                    title = stringResource(R.string.intent_import_pgp_key_title),
                    onBack = {
                        setResult(RESULT_CANCELED)
                        finish()
                    },
                ) { padding ->
                    Column(
                        Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(horizontal = 16.dp),
                    ) {
                        Text(status, modifier = Modifier.padding(top = 8.dp))
                        Button(
                            onClick = {
                                busy = true
                                error = null
                                scope.launch {
                                    try {
                                        val bytes = withContext(Dispatchers.IO) { readKeyBytes() }
                                            ?: error(getString(R.string.intent_no_key_data))
                                        ImportGuard.checkSize(bytes)
                                        val secret = looksLikeSecret(bytes)
                                        val info = withContext(Dispatchers.IO) {
                                            keyRepository.importKeyRing(bytes, secret)
                                        }
                                        status = getString(R.string.intent_imported_key_fmt, info.masterKeyId)
                                        setResult(RESULT_OK)
                                        finish()
                                    } catch (e: Exception) {
                                        error = e.message
                                        status = getString(R.string.intent_import_failed)
                                    } finally {
                                        busy = false
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                            enabled = !busy,
                        ) {
                            if (busy) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                            Text(stringResource(R.string.intent_import))
                        }
                        error?.let {
                            Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                        }
                    }
                }
        }
    }

    private fun readKeyBytes(): ByteArray? {
        intent.getByteArrayExtra(EXTRA_KEY_BYTES)?.let { return it }
        intent.getByteArrayExtra(PgpIntentActions.OKC_EXTRA_KEY_BYTES)?.let { return it }
        intent.getByteArrayExtra(PgpIntentActions.OKC_EXTRA_KEY_BYTES_ACTION)?.let { return it }
        @Suppress("DEPRECATION")
        intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)?.let { uri ->
            return readUri(uri)
        }
        // Local file / content URI (not fingerprint scheme).
        intent.data?.takeUnless { isOpenPgpFingerprintUri(it) }?.let { return readUri(it) }
        return fetchFromKeyserverOrNull()
    }

    /**
     * OpenKeychain [ACTION_IMPORT_KEY_FROM_KEYSERVER] extras / `openpgp4fpr:` data URI.
     * Uses the app's configured keyserver URL (fail closed when lookup is disabled).
     */
    private fun fetchFromKeyserverOrNull(): ByteArray? {
        val query = intentKeyserverQuery() ?: return null
        val settings = settingsRepository.current()
        if (!settings.keyserverLookupEnabled) {
            throw IllegalStateException(getString(R.string.keys_search_keyserver_disabled))
        }
        return keyserverClient.fetchKey(settings.keyserverUrl, query)
    }

    private fun intentKeyserverQuery(): String? {
        intent.getStringExtra(PgpIntentActions.OKC_EXTRA_FINGERPRINT)?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        intent.getStringExtra(PgpIntentActions.OKC_EXTRA_FINGERPRINT_ACTION)?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        intent.getStringExtra(PgpIntentActions.OKC_EXTRA_QUERY)?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        intent.getStringExtra(PgpIntentActions.OKC_EXTRA_QUERY_ACTION)?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        val keyId = intent.getLongExtra(PgpIntentActions.OKC_EXTRA_KEY_ID, 0L)
        if (keyId != 0L) {
            return keyId.toULong().toString(16).uppercase()
        }
        intent.data?.let { uri ->
            if (isOpenPgpFingerprintUri(uri)) {
                val fp = uri.schemeSpecificPart?.trim().orEmpty()
                if (fp.isNotEmpty()) return fp
            }
        }
        // Some callers put fingerprint in ACTION_IMPORT_KEY without stream/bytes.
        if (intent.action == ACTION_IMPORT_KEY_FROM_KEYSERVER ||
            intent.action == ACTION_IMPORT_KEY_FROM_QR_CODE ||
            intent.action == ACTION_IMPORT_KEY
        ) {
            intent.getStringExtra("fingerprint")?.trim()?.takeIf { it.isNotEmpty() }?.let { return it }
        }
        return null
    }

    private fun isOpenPgpFingerprintUri(uri: Uri): Boolean =
        uri.scheme.equals(OPENPGP4FPR_SCHEME, ignoreCase = true)

    private fun readUri(uri: Uri): ByteArray {
        return try {
            contentResolver.openInputStream(uri)?.use { PgpIo.readLimited(it) }
                ?: throw IllegalStateException(getString(R.string.intent_cannot_open_uri_fmt, uri))
        } catch (e: Exception) {
            throw IllegalStateException(getString(R.string.intent_failed_read_key_file), e)
        }
    }

    private fun looksLikeSecret(bytes: ByteArray): Boolean {
        // Armor headers or binary transferable secret key ring (GnuPG/Kleopatra .gpg).
        return ArmoredKeyDetector.isSecretMaterial(bytes) == true
    }

    /** Intent extras for launching the import screen. */
    companion object {
        /** Byte-array extra carrying raw key material to import directly. */
        const val EXTRA_KEY_BYTES = "key_bytes"

        private const val ACTION_IMPORT_KEY =
            "org.sufficientlysecure.keychain.action.IMPORT_KEY"
        private const val ACTION_IMPORT_KEY_FROM_KEYSERVER =
            "org.sufficientlysecure.keychain.action.IMPORT_KEY_FROM_KEYSERVER"
        private const val ACTION_IMPORT_KEY_FROM_QR_CODE =
            "org.sufficientlysecure.keychain.action.IMPORT_KEY_FROM_QR_CODE"
        private const val OPENPGP4FPR_SCHEME = "openpgp4fpr"
    }
}
