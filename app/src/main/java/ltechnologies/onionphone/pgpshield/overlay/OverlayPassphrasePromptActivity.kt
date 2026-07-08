package ltechnologies.onionphone.pgpshield.overlay

/**
 * Standalone activity that prompts for a key passphrase on behalf of the overlay.
 */

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import dagger.hilt.android.AndroidEntryPoint
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper
import javax.inject.Inject

/**
 * Secure, screenshot-protected passphrase entry screen launched by the overlay.
 *
 * On successful entry it stores the passphrase into [OverlayPassphraseSession]
 * keyed by the requested key id (passed via [EXTRA_KEY_ID]), zeroes the local
 * buffer and finishes with `RESULT_OK`.
 */
@AndroidEntryPoint
class OverlayPassphrasePromptActivity : ComponentActivity() {
    @Inject lateinit var session: OverlayPassphraseSession
    @Inject lateinit var settingsRepository: SettingsRepository

    /** Reads the target key id, binds screenshot policy and renders the prompt UI. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val keyId = intent.getLongExtra(EXTRA_KEY_ID, -1L)
        if (keyId < 0L) {
            finish()
            return
        }
        enableEdgeToEdge()
        setContent {
            PgpShieldTheme {
                var passphrase by remember { mutableStateOf("") }
                IntentFlowScaffold(
                    title = stringResource(R.string.overlay_passphrase_title),
                    onBack = { finish() },
                ) { padding ->
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(horizontal = 16.dp),
                    ) {
                        OutlinedTextField(
                            value = passphrase,
                            onValueChange = { passphrase = it },
                            label = { Text(stringResource(R.string.crypto_key_passphrase)) },
                            visualTransformation = PasswordVisualTransformation(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                        )
                        Button(
                            onClick = {
                                val chars = passphrase.toCharArray()
                                passphrase = ""
                                session.put(keyId, chars)
                                chars.fill('\u0000')
                                setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_KEY_ID, keyId))
                                finish()
                            },
                            enabled = passphrase.isNotBlank(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                        ) {
                            Text(stringResource(R.string.overlay_unlock))
                        }
                    }
                }
            }
        }
    }

    /** Intent extras for launching the prompt. */
    companion object {
        /** Long extra carrying the master key id whose passphrase is requested. */
        const val EXTRA_KEY_ID = "overlay_key_id"
    }
}
