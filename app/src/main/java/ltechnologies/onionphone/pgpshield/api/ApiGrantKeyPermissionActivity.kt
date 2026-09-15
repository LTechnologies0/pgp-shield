package ltechnologies.onionphone.pgpshield.api

/**
 * OpenKeychain-style per-key permission grant for OpenPGP API decrypt.
 *
 * When ciphertext targets a local secret that is not on the calling app's
 * allowlist, [OpenPgpApiService] returns USER_INTERACTION with this activity.
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
import androidx.lifecycle.lifecycleScope
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.launch
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.data.db.ApiAllowedKeyDao
import ltechnologies.onionphone.pgpshield.data.db.ApiAllowedKeyEntity
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.CallerVerifier
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper

@AndroidEntryPoint
class ApiGrantKeyPermissionActivity : ComponentActivity() {
    @Inject lateinit var apiAllowedKeyDao: ApiAllowedKeyDao
    @Inject lateinit var settingsRepository: SettingsRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val packageName = intent.getStringExtra(EXTRA_PACKAGE) ?: run {
            finish()
            return
        }
        val keyIds = intent.getLongArrayExtra(EXTRA_KEY_IDS)?.filter { it != 0L }?.distinct().orEmpty()
        if (keyIds.isEmpty()) {
            setResult(Activity.RESULT_CANCELED)
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
                    title = stringResource(R.string.api_grant_key_title),
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
                        if (verifyError != null) {
                            Text(
                                verifyError,
                                color = MaterialTheme.colorScheme.error,
                                modifier = Modifier.padding(vertical = 12.dp),
                            )
                            Button(
                                onClick = {
                                    setResult(Activity.RESULT_CANCELED)
                                    finish()
                                },
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text(stringResource(R.string.common_close)) }
                        } else {
                            Text(
                                stringResource(
                                    R.string.api_grant_key_message_fmt,
                                    packageName,
                                    keyIds.size,
                                ),
                                modifier = Modifier.padding(vertical = 12.dp),
                                style = MaterialTheme.typography.bodyMedium,
                            )
                            Button(
                                onClick = {
                                    lifecycleScope.launch {
                                        for (keyId in keyIds) {
                                            apiAllowedKeyDao.insert(
                                                ApiAllowedKeyEntity(packageName = packageName, keyId = keyId),
                                            )
                                        }
                                        setResult(Activity.RESULT_OK)
                                        finish()
                                    }
                                },
                                modifier = Modifier.fillMaxWidth(),
                            ) { Text(stringResource(R.string.api_grant)) }
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
    }

    companion object {
        const val EXTRA_PACKAGE = "package"
        const val EXTRA_KEY_IDS = "key_ids"
    }
}
