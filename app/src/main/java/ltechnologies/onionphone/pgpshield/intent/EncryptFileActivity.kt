package ltechnologies.onionphone.pgpshield.intent

/**
 * Intent-launched screen for encrypting a single file payload.
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
import androidx.compose.runtime.LaunchedEffect
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
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Handles incoming encrypt-file intents.
 *
 * Reads the file payload, encrypts it to the resolved recipient key, then either
 * writes the ciphertext back for an integrating caller (auto-run mode) or offers
 * a share chooser for interactive use.
 */
@AndroidEntryPoint
class EncryptFileActivity : ComponentActivity() {
    @Inject lateinit var cryptoOperations: CryptoOperations
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var settingsRepository: SettingsRepository

    /** Builds the encrypt UI and, in integration mode, auto-runs encryption. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val integrationMode = IntentResultWriter.isCallerIntegration(intent)
        val fileName = intent.data?.lastPathSegment ?: getString(R.string.intent_default_file)
        setContent {
            PgpShieldTheme {
                var status by remember { mutableStateOf(getString(R.string.intent_status_ready_encrypt_fmt, fileName)) }
                var error by remember { mutableStateOf<String?>(null) }
                var busy by remember { mutableStateOf(false) }
                var started by remember { mutableStateOf(false) }
                val scope = rememberCoroutineScope()

                val runEncrypt: () -> Unit = {
                    if (!busy) {
                        busy = true
                        error = null
                        scope.launch {
                            try {
                                encryptAndDeliver(fileName)
                            } catch (e: Exception) {
                                error = e.message
                                status = getString(R.string.intent_status_encryption_failed)
                                if (integrationMode) {
                                    IntentResultWriter.finishCancel(this@EncryptFileActivity)
                                }
                            } finally {
                                busy = false
                            }
                        }
                    }
                }

                if (integrationMode) {
                    LaunchedEffect(Unit) {
                        if (!started) {
                            started = true
                            runEncrypt()
                        }
                    }
                }

                IntentFlowScaffold(
                    title = stringResource(R.string.crypto_encrypt_file_action),
                    onBack = { finish() },
                ) { padding ->
                    Column(
                        Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(horizontal = 16.dp),
                    ) {
                        Text(status, modifier = Modifier.padding(top = 8.dp))
                        if (!integrationMode) {
                            Button(
                                onClick = runEncrypt,
                                modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                                enabled = !busy,
                            ) {
                                if (busy) {
                                    CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                                }
                                Text(stringResource(R.string.intent_encrypt_and_share))
                            }
                        } else if (busy) {
                            CircularProgressIndicator(modifier = Modifier.padding(top = 16.dp))
                        }
                        error?.let {
                            Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                        }
                    }
                }
            }
        }
    }

    private suspend fun encryptAndDeliver(fileName: String) {
        val bytes = IntentIoHelper.readBytes(intent, this)
            ?: error("Could not read file from intent")
        val public = IntentIoHelper.loadEncryptPublicKey(keyRepository, settingsRepository)
        val encrypted = withContext(Dispatchers.Default) {
            cryptoOperations.encrypt(bytes, listOf(public), asciiArmor = false)
        }
        val sourcePaths = intent.getStringArrayListExtra(PgpIntentActions.EXTRA_SOURCE_PATHS)
        if (!sourcePaths.isNullOrEmpty()) {
            val outFile = IntentResultWriter.writeEncryptedForCaller(intent, sourcePaths.first(), encrypted.ciphertext)
            IntentResultWriter.finishOk(this)
            return
        }
        val uri = IntentIoHelper.writeShareFile(this, encrypted.ciphertext, "$fileName.gpg")
        shareEncryptedFile(uri)
    }

    private fun shareEncryptedFile(uri: Uri) {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(send, getString(R.string.intent_share_encrypted_file)))
    }
}
