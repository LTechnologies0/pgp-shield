package ltechnologies.onionphone.pgpshield.intent

/**
 * Intent-launched screen for decrypting armored PGP text.
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
import androidx.compose.material3.MaterialTheme
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
 * Handles incoming decrypt-text intents.
 *
 * Pre-fills the ciphertext from the intent, decrypts it with the resolved secret
 * key and a user-supplied passphrase, then displays and optionally shares the
 * plaintext. Passphrase buffers are wiped after each attempt.
 */
@AndroidEntryPoint
class DecryptTextActivity : ComponentActivity() {
    @Inject lateinit var cryptoOperations: CryptoOperations
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var settingsRepository: SettingsRepository

    /** Builds the decrypt-text UI and wires up the decrypt/share action. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        setContent {
            PgpShieldTheme {
                var ciphertext by remember { mutableStateOf("") }
                LaunchedEffect(Unit) {
                    ciphertext = IntentIoHelper.readText(intent, this@DecryptTextActivity).orEmpty()
                }
                var plaintext by remember { mutableStateOf("") }
                var passphrase by remember { mutableStateOf("") }
                var errorMessage by remember { mutableStateOf<String?>(null) }
                var busy by remember { mutableStateOf(false) }
                val scope = rememberCoroutineScope()

                IntentFlowScaffold(
                    title = stringResource(R.string.intent_decrypt_text_title),
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
                            value = ciphertext,
                            onValueChange = { ciphertext = it; errorMessage = null },
                            label = { Text(stringResource(R.string.crypto_armored_ciphertext)) },
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                            minLines = 4,
                        )
                        OutlinedTextField(
                            value = passphrase,
                            onValueChange = { passphrase = it },
                            label = { Text(stringResource(R.string.intent_passphrase)) },
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        )
                        Button(
                            onClick = {
                                busy = true
                                errorMessage = null
                                var pass: CharArray? = null
                                scope.launch {
                                    try {
                                        val secret = IntentIoHelper.loadDecryptSecretKey(keyRepository, settingsRepository)
                                        val passChars = passphrase.takeIf { it.isNotBlank() }?.toCharArray()
                                            ?: error("Enter passphrase")
                                        pass = passChars
                                        val result = withContext(Dispatchers.Default) {
                                            cryptoOperations.decrypt(
                                                ciphertext.toByteArray(Charsets.UTF_8),
                                                secret,
                                                passChars,
                                            )
                                        }
                                        plaintext = String(result.plaintext, Charsets.UTF_8)
                                    } catch (e: Exception) {
                                        errorMessage = e.message
                                    } finally {
                                        pass?.fill('\u0000')
                                        busy = false
                                    }
                                }
                            },
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                            enabled = ciphertext.isNotBlank() && passphrase.isNotBlank() && !busy,
                        ) {
                            if (busy) CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                            Text(stringResource(R.string.crypto_decrypt_action))
                        }
                        if (plaintext.isNotBlank()) {
                            OutlinedTextField(
                                value = plaintext,
                                onValueChange = {},
                                readOnly = true,
                                label = { Text(stringResource(R.string.crypto_plaintext)) },
                                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                                minLines = 4,
                            )
                            Button(
                                onClick = {
                                    startActivity(
                                        Intent.createChooser(
                                            Intent(Intent.ACTION_SEND).apply {
                                                type = "text/plain"
                                                putExtra(Intent.EXTRA_TEXT, plaintext)
                                            },
                                            getString(R.string.intent_share_plaintext),
                                        ),
                                    )
                                },
                                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                            ) { Text(stringResource(R.string.common_share)) }
                        }
                        errorMessage?.let { msg ->
                            Text(msg, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                        }
                    }
                }
            }
        }
    }
}
