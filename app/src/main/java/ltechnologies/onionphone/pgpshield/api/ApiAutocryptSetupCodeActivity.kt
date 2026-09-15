package ltechnologies.onionphone.pgpshield.api

/**
 * Shows the Autocrypt Setup Message transfer code after [ACTION_AUTOCRYPT_KEY_TRANSFER].
 *
 * OpenKeychain returns this via [OpenPgpConstants.RESULT_INTENT] so the mail client
 * can surface the 9×4 digit code the recipient must enter on the other device.
 */

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper

@AndroidEntryPoint
class ApiAutocryptSetupCodeActivity : ComponentActivity() {
    @Inject lateinit var settingsRepository: SettingsRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        enableEdgeToEdge()
        val code = intent.getStringExtra(EXTRA_SETUP_CODE).orEmpty()
        setContent {
            PgpShieldTheme {
                IntentFlowScaffold(
                    title = stringResource(R.string.api_autocrypt_setup_code_title),
                    onBack = {
                        setResult(Activity.RESULT_CANCELED)
                        finish()
                    },
                ) { padding ->
                    Column(
                        Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(horizontal = 16.dp),
                    ) {
                        Text(
                            stringResource(R.string.api_autocrypt_setup_code_message),
                            modifier = Modifier.padding(top = 12.dp, bottom = 16.dp),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        SelectionContainer {
                            Text(
                                code,
                                modifier = Modifier.padding(bottom = 24.dp),
                                style = MaterialTheme.typography.headlineSmall,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                        Button(
                            onClick = {
                                setResult(Activity.RESULT_OK)
                                finish()
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(stringResource(android.R.string.ok))
                        }
                    }
                }
            }
        }
    }

    companion object {
        const val EXTRA_SETUP_CODE = "autocrypt_setup_code"
    }
}
