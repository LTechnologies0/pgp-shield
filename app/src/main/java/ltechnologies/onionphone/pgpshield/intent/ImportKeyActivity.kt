package ltechnologies.onionphone.pgpshield.intent

/**
 * Intent-launched screen for importing an OpenPGP key from a file or bytes.
 */

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
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
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Handles incoming key-import intents (OpenKeychain-compatible import actions).
 *
 * Reads key bytes from an extra, `EXTRA_STREAM` or the data URI, enforces a size
 * guard, auto-detects secret vs. public material and imports it into the store.
 */
@AndroidEntryPoint
class ImportKeyActivity : ComponentActivity() {
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var settingsRepository: SettingsRepository

    /** Builds the import UI and wires up the import action. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val label = intent.data?.lastPathSegment ?: getString(R.string.intent_default_key)
        setContent {
            PgpShieldTheme {
                var status by remember { mutableStateOf(getString(R.string.intent_import_key_status_fmt, label)) }
                var error by remember { mutableStateOf<String?>(null) }
                var busy by remember { mutableStateOf(false) }
                val scope = rememberCoroutineScope()

                IntentFlowScaffold(
                    title = stringResource(R.string.intent_import_pgp_key_title),
                    onBack = { finish() },
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
                                            ?: error("No key data in intent")
                                        ImportGuard.checkSize(bytes)
                                        val secret = looksLikeSecret(bytes)
                                        val info = withContext(Dispatchers.IO) {
                                            keyRepository.importKeyRing(bytes, secret)
                                        }
                                        status = getString(R.string.intent_imported_key_fmt, info.masterKeyId)
                                        setResult(RESULT_OK)
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
    }

    private fun readKeyBytes(): ByteArray? {
        intent.getByteArrayExtra(EXTRA_KEY_BYTES)?.let { return it }
        @Suppress("DEPRECATION")
        intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)?.let { uri ->
            return readUri(uri)
        }
        intent.data?.let { return readUri(it) }
        return null
    }

    private fun readUri(uri: Uri): ByteArray {
        return try {
            contentResolver.openInputStream(uri)?.use { PgpIo.readLimited(it) }
                ?: throw IllegalStateException("Cannot open $uri")
        } catch (e: Exception) {
            throw IllegalStateException("Failed to read key file", e)
        }
    }

    private fun looksLikeSecret(armored: ByteArray): Boolean {
        val text = String(armored, Charsets.UTF_8)
        return text.contains("PRIVATE KEY BLOCK", ignoreCase = true)
    }

    /** Intent extras for launching the import screen. */
    companion object {
        /** Byte-array extra carrying raw key material to import directly. */
        const val EXTRA_KEY_BYTES = "key_bytes"
    }
}
