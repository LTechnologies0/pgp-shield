package ltechnologies.onionphone.pgpshield.intent

/**
 * Intent-launched screen for encrypting plaintext to a PGP message.
 */

import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextField
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
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Handles incoming encrypt-text intents.
 *
 * Pre-fills the plaintext from the intent, encrypts it to the configured default
 * recipient (or first available key), and lets the user share the resulting
 * armored ciphertext.
 */
@AndroidEntryPoint
class EncryptTextActivity : ComponentActivity() {
    @Inject lateinit var cryptoOperations: CryptoOperations
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var settingsRepository: SettingsRepository

    /** Builds the encrypt-text UI and wires up the encrypt/share action. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        setContent {
            PgpShieldTheme {
                var plaintext by remember { mutableStateOf("") }
                LaunchedEffect(Unit) {
                    plaintext = IntentIoHelper.readText(intent, this@EncryptTextActivity).orEmpty()
                }
                var output by remember { mutableStateOf("") }
                var error by remember { mutableStateOf<String?>(null) }
                var busy by remember { mutableStateOf(false) }
                val scope = rememberCoroutineScope()

                IntentFlowScaffold(
                    title = stringResource(R.string.intent_encrypt_text_title),
                    onBack = { finish() },
                ) { padding ->
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(horizontal = 16.dp)
                            .verticalScroll(rememberScrollState()),
                    ) {
                        OutlinedTextField(
                            value = plaintext,
                            onValueChange = { plaintext = it; error = null },
                            label = { Text(stringResource(R.string.crypto_plaintext)) },
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                            minLines = 4,
                        )
                        Button(
                            onClick = {
                                busy = true
                                error = null
                                scope.launch {
                                    try {
                                        val public = withContext(Dispatchers.IO) {
                                            val settings = settingsRepository.current()
                                            val allKeys = keyRepository.observeKeys().first()
                                            val keyId = settings.defaultEncryptKeyId ?: allKeys.firstOrNull()?.masterKeyId
                                            keyId?.let { keyRepository.getArmoredPublic(it) }
                                                ?: error("No recipient key — set default in Settings or import a public key")
                                        }
                                        val result = withContext(Dispatchers.Default) {
                                            cryptoOperations.encrypt(plaintext.toByteArray(Charsets.UTF_8), listOf(public))
                                        }
                                        output = String(result.ciphertext, Charsets.UTF_8)
                                    } catch (e: Exception) {
                                        error = e.message
                                    } finally {
                                        busy = false
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                            enabled = plaintext.isNotBlank() && !busy,
                        ) {
                            if (busy) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                            Text(stringResource(R.string.crypto_encrypt_action))
                        }
                        if (output.isNotBlank()) {
                            OutlinedTextField(
                                value = output,
                                onValueChange = {},
                                readOnly = true,
                                label = { Text(stringResource(R.string.intent_ciphertext)) },
                                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                                minLines = 6,
                            )
                            Button(
                                onClick = { shareText(output) },
                                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                            ) { Text(stringResource(R.string.common_share)) }
                        }
                        error?.let {
                            Text(it, color = androidx.compose.material3.MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                        }
                    }
                }
            }
        }
    }

    private fun shareText(text: String) {
        startActivity(
            Intent.createChooser(
                Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, text)
                },
                getString(R.string.intent_share_encrypted_text),
            ),
        )
    }
}
