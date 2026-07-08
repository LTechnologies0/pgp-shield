package ltechnologies.onionphone.pgpshield.api

/**
 * Consent screen shown when an external app requests OpenPGP API access.
 */

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import dagger.hilt.android.AndroidEntryPoint
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.data.db.ApiAppDao
import ltechnologies.onionphone.pgpshield.data.db.ApiAppEntity
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.CallerVerifier
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper
import javax.inject.Inject
import kotlinx.coroutines.launch

/**
 * Prompts the user to grant or deny API access to a calling package.
 *
 * The requesting package is verified against the calling UID via
 * [CallerVerifier]; on approval an [ApiAppEntity] grant is persisted and
 * `RESULT_OK` is returned, otherwise `RESULT_CANCELED`.
 */
@AndroidEntryPoint
class GrantApiAccessActivity : ComponentActivity() {
    @Inject lateinit var apiAppDao: ApiAppDao
    @Inject lateinit var settingsRepository: SettingsRepository

    /** Verifies the caller and renders the grant/deny consent UI. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val packageName = intent.getStringExtra(EXTRA_PACKAGE) ?: run {
            finish()
            return
        }
        val verifyError = try {
            CallerVerifier.verifiedPackageFromIntent(this, packageName)
            null
        } catch (e: Exception) {
            e.message ?: getString(R.string.api_verify_failed)
        }
        enableEdgeToEdge()
        setContent {
            PgpShieldTheme {
                IntentFlowScaffold(
                    title = if (verifyError != null) {
                        stringResource(R.string.api_verify_failed)
                    } else {
                        stringResource(R.string.api_allow_access_title)
                    },
                    onBack = {
                        setResult(RESULT_CANCELED)
                        finish()
                    },
                ) { padding ->
                    Column(
                        Modifier
                            .fillMaxSize()
                            .padding(padding)
                            .padding(horizontal = 16.dp),
                    ) {
                        if (verifyError != null) {
                            Text(
                                verifyError,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.padding(vertical = 12.dp),
                            )
                            Button(
                                onClick = {
                                    setResult(RESULT_CANCELED)
                                    finish()
                                },
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text(stringResource(R.string.common_close)) }
                        } else {
                            Text(
                                stringResource(R.string.api_allow_access_message_fmt, packageName),
                                modifier = Modifier.padding(vertical = 12.dp),
                            )
                            Button(
                                onClick = {
                                    lifecycleScope.launch {
                                        apiAppDao.grant(ApiAppEntity(packageName, System.currentTimeMillis()))
                                        setResult(RESULT_OK)
                                        finish()
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text(stringResource(R.string.api_grant)) }
                            Button(
                                onClick = {
                                    setResult(RESULT_CANCELED)
                                    finish()
                                },
                                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                            ) { Text(stringResource(R.string.api_deny)) }
                        }
                    }
                }
            }
        }
    }

    /** Intent extras for launching the consent screen. */
    companion object {
        /** String extra naming the package requesting API access. */
        const val EXTRA_PACKAGE = "package"
    }
}
