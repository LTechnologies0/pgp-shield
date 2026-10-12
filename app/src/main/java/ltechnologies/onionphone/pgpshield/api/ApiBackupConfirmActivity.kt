package ltechnologies.onionphone.pgpshield.api

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
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
import ltechnologies.onionphone.pgpshield.util.CallerVerifier
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper

/** Always-on confirmation before a secret-key backup leaves the vault. */
@AndroidEntryPoint
class ApiBackupConfirmActivity : ComponentActivity() {
    @Inject lateinit var settingsRepository: SettingsRepository
    @Inject lateinit var backupConfirmCache: ApiBackupConfirmCache

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val packageName = intent.getStringExtra(EXTRA_PACKAGE) ?: run {
            finish()
            return
        }
        val keyIds = intent.getLongArrayExtra(EXTRA_KEY_IDS)?.toList().orEmpty()
        try {
            CallerVerifier.packageFromImmutableGrant(this, packageName)
        } catch (_: Exception) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }
        enableEdgeToEdge()
        setContent {
            PgpShieldTheme {
                IntentFlowScaffold(
                    title = stringResource(R.string.api_backup_confirm_title),
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
                            stringResource(R.string.api_backup_confirm_message_fmt, packageName, keyIds.size),
                            modifier = Modifier.padding(vertical = 12.dp),
                        )
                        Button(
                            onClick = {
                                backupConfirmCache.markConfirmed(packageName, keyIds)
                                setResult(Activity.RESULT_OK)
                                finish()
                            },
                            modifier = Modifier.fillMaxWidth(),
                        ) { Text(stringResource(R.string.api_backup_confirm_export)) }
                        Button(
                            onClick = {
                                setResult(Activity.RESULT_CANCELED)
                                finish()
                            },
                            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                        ) { Text(stringResource(R.string.api_deny)) }
                    }
                }
            }
        }
    }

    companion object {
        const val EXTRA_PACKAGE = "package"
        const val EXTRA_KEY_IDS = "key_ids"
    }
}
