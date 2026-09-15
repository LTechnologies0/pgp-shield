package ltechnologies.onionphone.pgpshield.api

/**
 * OpenPGP API sign-key picker returned via USER_INTERACTION_REQUIRED.
 *
 * Clients (K-9, FairEmail, OpenKeychain-compatible) launch the PendingIntent,
 * then re-execute with [OpenPgpConstants.EXTRA_SIGN_KEY_ID] from the result.
 */

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.lifecycleScope
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.openpgp.OpenPgpConstants
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.components.formatKeySummaryLine
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper

@AndroidEntryPoint
class ApiSelectSignKeyActivity : ComponentActivity() {
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var settingsRepository: SettingsRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        enableEdgeToEdge()
        val preferredEmail = intent.getStringExtra(OpenPgpConstants.EXTRA_USER_ID)
            ?.let { raw ->
                val trimmed = raw.trim()
                val fromAngles = trimmed.substringAfter('<', missingDelimiterValue = "")
                    .substringBefore('>', missingDelimiterValue = "")
                    .trim()
                (fromAngles.ifBlank { trimmed }).lowercase().takeIf { it.contains('@') }
            }
        val preselectId = intent.getLongExtra(OpenPgpConstants.EXTRA_PRESELECT_KEY_ID, 0L)
            .takeIf { it != 0L }
        val showAutocryptHint = intent.getBooleanExtra(OpenPgpConstants.EXTRA_SHOW_AUTOCRYPT_HINT, false)
        val secretKeysFlow = keyRepository.observeKeys().map { list ->
            val secrets = list.filter { it.isSecret }
            secrets.sortedWith(
                compareByDescending<ltechnologies.onionphone.pgpshield.data.KeySummary> { key ->
                    preselectId != null && key.masterKeyId == preselectId
                }.thenByDescending { key ->
                    if (preferredEmail == null) false
                    else {
                        val uid = key.primaryUserId?.lowercase().orEmpty()
                        preferredEmail in uid || uid.contains("<$preferredEmail>")
                    }
                },
            )
        }
        setContent {
            PgpShieldTheme {
                val keys by secretKeysFlow.collectAsState(initial = emptyList())
                IntentFlowScaffold(
                    title = stringResource(R.string.api_select_sign_key_title),
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
                            stringResource(R.string.api_select_sign_key_message),
                            modifier = Modifier.padding(top = 12.dp, bottom = 8.dp),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        if (showAutocryptHint) {
                            Text(
                                stringResource(R.string.api_select_sign_key_autocrypt_hint),
                                modifier = Modifier.padding(bottom = 8.dp),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.secondary,
                            )
                        }
                        if (preferredEmail != null) {
                            Text(
                                preferredEmail,
                                modifier = Modifier.padding(bottom = 8.dp),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                        if (keys.isEmpty()) {
                            Text(
                                stringResource(R.string.api_err_no_secret_keys),
                                color = MaterialTheme.colorScheme.error,
                            )
                        } else {
                            LazyColumn(Modifier.fillMaxWidth()) {
                                items(keys, key = { it.masterKeyId }) { key ->
                                    Text(
                                        formatKeySummaryLine(key),
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable {
                                                lifecycleScope.launch {
                                                    settingsRepository.update {
                                                        it.copy(defaultSignKeyId = key.masterKeyId)
                                                    }
                                                    setResult(
                                                        Activity.RESULT_OK,
                                                        Intent()
                                                            .putExtra(
                                                                OpenPgpConstants.EXTRA_SIGN_KEY_ID,
                                                                key.masterKeyId,
                                                            )
                                                            .putExtra(
                                                                OpenPgpConstants.RESULT_SIGN_KEY_ID,
                                                                key.masterKeyId,
                                                            )
                                                            .apply {
                                                                key.primaryUserId?.let {
                                                                    putExtra(
                                                                        OpenPgpConstants.RESULT_PRIMARY_USER_ID,
                                                                        it,
                                                                    )
                                                                }
                                                                if (key.createdAt > 0L) {
                                                                    putExtra(
                                                                        OpenPgpConstants.RESULT_KEY_CREATION_TIME,
                                                                        key.createdAt,
                                                                    )
                                                                }
                                                            },
                                                    )
                                                    finish()
                                                }
                                            }
                                            .padding(vertical = 14.dp),
                                    )
                                    HorizontalDivider()
                                }
                            }
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
