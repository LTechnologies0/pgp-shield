package ltechnologies.onionphone.pgpshield.intent

/**
 * Intent-launched screen for decrypting an encrypted file payload.
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
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
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
 * Handles incoming decrypt-file intents.
 *
 * Reads the encrypted payload from the intent, prompts for a passphrase, and
 * either writes the plaintext back for an integrating caller or shares it via a
 * `FileProvider` chooser. The window is screenshot-protected and passphrase
 * buffers are wiped after use.
 */
@AndroidEntryPoint
class DecryptFileActivity : ComponentActivity() {
    @Inject lateinit var cryptoOperations: CryptoOperations
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var settingsRepository: SettingsRepository

    /** Builds the decrypt UI and wires up the decrypt/share action. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val fileName = intent.data?.lastPathSegment ?: getString(R.string.intent_default_encrypted_file)
        setContent {
            PgpShieldTheme {
                var status by remember { mutableStateOf(getString(R.string.intent_status_ready_decrypt_fmt, fileName)) }
                var passphrase by remember { mutableStateOf("") }
                var error by remember { mutableStateOf<String?>(null) }
                var busy by remember { mutableStateOf(false) }
                val scope = rememberCoroutineScope()

                IntentFlowScaffold(
                    title = stringResource(R.string.crypto_decrypt_file_action),
                    onBack = { finish() },
                ) { padding ->
                    Column(
                        Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(horizontal = 16.dp),
                    ) {
                        Text(status, modifier = Modifier.padding(top = 8.dp))
                        OutlinedTextField(
                            value = passphrase,
                            onValueChange = { passphrase = it },
                            label = { Text(stringResource(R.string.crypto_key_passphrase)) },
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        )
                        Button(
                            onClick = {
                                busy = true
                                error = null
                                var pass: CharArray? = null
                                scope.launch {
                                    try {
                                        val bytes = IntentIoHelper.readBytes(intent, this@DecryptFileActivity)
                                            ?: error("Could not read file from intent")
                                        val secret = IntentIoHelper.loadDecryptSecretKey(keyRepository, settingsRepository)
                                        val passChars = passphrase.takeIf { it.isNotBlank() }?.toCharArray()
                                            ?: error("Enter passphrase")
                                        pass = passChars
                                        val decrypted = withContext(Dispatchers.Default) {
                                            cryptoOperations.decrypt(bytes, secret, passChars)
                                        }
                                        val sourcePaths = intent.getStringArrayListExtra(PgpIntentActions.EXTRA_SOURCE_PATHS)
                                        if (!sourcePaths.isNullOrEmpty()) {
                                            val outFile = IntentResultWriter.writeDecryptedForCaller(
                                                intent,
                                                sourcePaths.first(),
                                                decrypted.plaintext,
                                            )
                                            IntentResultWriter.finishOk(this@DecryptFileActivity)
                                            return@launch
                                        }
                                        val uri = IntentIoHelper.writeShareFile(
                                            this@DecryptFileActivity,
                                            decrypted.plaintext,
                                            strippedName(fileName),
                                        )
                                        shareDecryptedFile(uri)
                                        status = getString(R.string.intent_status_decrypted_share)
                                    } catch (e: Exception) {
                                        error = e.message
                                        status = getString(R.string.intent_status_decryption_failed)
                                    } finally {
                                        pass?.fill('\u0000')
                                        busy = false
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth().padding(top = 16.dp),
                            enabled = !busy && passphrase.isNotBlank(),
                        ) {
                            if (busy) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                            Text(stringResource(R.string.intent_decrypt_and_share))
                        }
                        error?.let {
                            Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                        }
                    }
                }
            }
        }
    }

    private fun strippedName(name: String): String = IntentResultWriter.decryptedOutputName(name)

    private fun shareDecryptedFile(uri: Uri) {
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "application/octet-stream"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        startActivity(Intent.createChooser(send, getString(R.string.intent_share_decrypted_file)))
    }
}
