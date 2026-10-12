package ltechnologies.onionphone.pgpshield.overlay

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
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

/** FLAG_SECURE window that shows overlay decrypt plaintext (never clipboard-only). */
@AndroidEntryPoint
class OverlayPlaintextActivity : ComponentActivity() {
    @Inject lateinit var settingsRepository: SettingsRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val plaintext = intent.getStringExtra(EXTRA_PLAINTEXT).orEmpty()
        if (plaintext.isEmpty()) {
            finish()
            return
        }
        enableEdgeToEdge()
        setContent {
            PgpShieldTheme {
                IntentFlowScaffold(
                    title = stringResource(R.string.overlay_plaintext_title),
                    onBack = { finish() },
                ) { padding ->
                    Column(
                        Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(horizontal = 16.dp)
                            .verticalScroll(rememberScrollState()),
                    ) {
                        OutlinedTextField(
                            value = plaintext,
                            onValueChange = {},
                            readOnly = true,
                            label = { Text(stringResource(R.string.crypto_plaintext)) },
                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                            minLines = 8,
                        )
                        Button(
                            onClick = { finish() },
                            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                        ) { Text(stringResource(R.string.common_close)) }
                    }
                }
            }
        }
    }

    companion object {
        const val EXTRA_PLAINTEXT = "overlay_plaintext"
    }
}
