package ltechnologies.onionphone.pgpshield.api

/**
 * OpenPGP API detail screen for [OpenPgpConstants.RESULT_INSECURE_DETAIL_INTENT].
 *
 * Mail clients (K-9 / FairEmail) open this PendingIntent when decryption or
 * signature verification reports insecure cryptography. Confirming stores an
 * override so `RESULT_OVERRIDE_CRYPTO_WARNING` becomes true on the next call.
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
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.CryptoWarningOverrideStore
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper

@AndroidEntryPoint
class ApiInsecureCryptoActivity : ComponentActivity() {
    @Inject lateinit var settingsRepository: SettingsRepository
    @Inject lateinit var cryptoWarningOverrideStore: CryptoWarningOverrideStore

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        enableEdgeToEdge()
        val detail = intent.getStringExtra(EXTRA_DETAIL)
            ?: getString(R.string.api_insecure_crypto_body)
        val problemId = intent.getStringExtra(EXTRA_PROBLEM_ID).orEmpty()
        setContent {
            PgpShieldTheme {
                IntentFlowScaffold(
                    title = stringResource(R.string.api_insecure_crypto_title),
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
                            detail,
                            modifier = Modifier.padding(top = 12.dp, bottom = 16.dp),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        Button(
                            onClick = {
                                if (problemId.isNotEmpty()) {
                                    cryptoWarningOverrideStore.setOverridden(problemId)
                                }
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
        const val EXTRA_DETAIL = "insecure_detail"
        const val EXTRA_PROBLEM_ID = "insecure_problem_id"
    }
}
