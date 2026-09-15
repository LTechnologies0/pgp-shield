package ltechnologies.onionphone.pgpshield.api

/**
 * Passphrase prompt returned via OpenPGP API USER_INTERACTION_REQUIRED.
 *
 * OpenKeychain-compatible clients launch the PendingIntent, then re-execute the
 * API call using the returned Intent extras (including [OpenPgpConstants.EXTRA_PASSPHRASE]).
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
import ltechnologies.onionphone.pgpshield.openpgp.OpenPgpConstants
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper
import javax.inject.Inject

@AndroidEntryPoint
class ApiPassphraseActivity : ComponentActivity() {
    @Inject lateinit var settingsRepository: SettingsRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        enableEdgeToEdge()
        setContent {
            PgpShieldTheme {
                var passphrase by remember { mutableStateOf("") }
                IntentFlowScaffold(
                    title = stringResource(R.string.api_passphrase_title),
                    onBack = {
                        setResult(Activity.RESULT_CANCELED)
                        finish()
                    },
                ) { padding ->
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(horizontal = 16.dp),
                    ) {
                        Text(
                            stringResource(R.string.api_passphrase_message),
                            modifier = Modifier.padding(top = 12.dp),
                        )
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
                                setResult(
                                    Activity.RESULT_OK,
                                    Intent().putExtra(OpenPgpConstants.EXTRA_PASSPHRASE, chars),
                                )
                                chars.fill('\u0000')
                                finish()
                            },
                            enabled = passphrase.isNotBlank(),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(top = 12.dp),
                        ) {
                            Text(stringResource(R.string.api_passphrase_continue))
                        }
                    }
                }
            }
        }
    }

    companion object {
        const val EXTRA_CALLER_PACKAGE = "caller_package"
    }
}
