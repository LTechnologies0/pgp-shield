package ltechnologies.onionphone.pgpshield.api

/**
 * OpenPGP API encrypt-recipient picker returned via USER_INTERACTION_REQUIRED.
 *
 * Clients launch the PendingIntent, then re-execute ENCRYPT with
 * [OpenPgpConstants.EXTRA_KEY_IDS_SELECTED] from the result.
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
import androidx.compose.material3.Button
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.flow.map
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeySummary
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.openpgp.OpenPgpConstants
import ltechnologies.onionphone.pgpshield.ui.components.IntentFlowScaffold
import ltechnologies.onionphone.pgpshield.ui.components.formatKeySummaryLine
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper

@AndroidEntryPoint
class ApiSelectEncryptKeyActivity : ComponentActivity() {
    @Inject lateinit var keyRepository: KeyRepository
    @Inject lateinit var settingsRepository: SettingsRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        enableEdgeToEdge()
        val preferredEmails = intent.getStringArrayExtra(OpenPgpConstants.EXTRA_USER_IDS)
            ?.mapNotNull { normalizeEmail(it) }
            ?.toSet()
            .orEmpty()
        val recipientsFlow = keyRepository.observeKeys().map { list ->
            val candidates = list.filter { it.isEncryptPickerCandidate() }
            if (preferredEmails.isEmpty()) {
                candidates
            } else {
                val matching = candidates.filter { key -> uidMatchesAny(key, preferredEmails) }
                // Prefer matches for the caller's To:/Cc:; fall back to full list if none.
                val ordered = (matching + candidates.filterNot { it in matching })
                ordered.distinctBy { it.masterKeyId }
            }
        }
        setContent {
            PgpShieldTheme {
                val keys by recipientsFlow.collectAsState(initial = emptyList())
                var selected by remember { mutableStateOf(setOf<Long>()) }
                IntentFlowScaffold(
                    title = stringResource(R.string.api_select_encrypt_key_title),
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
                            stringResource(R.string.api_select_encrypt_key_message),
                            modifier = Modifier.padding(top = 12.dp, bottom = 8.dp),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        if (preferredEmails.isNotEmpty()) {
                            Text(
                                preferredEmails.joinToString(", "),
                                modifier = Modifier.padding(bottom = 8.dp),
                                style = MaterialTheme.typography.labelMedium,
                                color = MaterialTheme.colorScheme.primary,
                            )
                        }
                        if (keys.isEmpty()) {
                            Text(
                                stringResource(R.string.api_err_no_recipients),
                                color = MaterialTheme.colorScheme.error,
                            )
                        } else {
                            LazyColumn(modifier = Modifier.weight(1f).fillMaxWidth()) {
                                items(keys, key = { it.masterKeyId }) { key ->
                                    val on = key.masterKeyId in selected
                                    Text(
                                        buildString {
                                            append(if (on) "✓ " else "○ ")
                                            append(formatKeySummaryLine(key))
                                        },
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .clickable {
                                                selected = if (on) {
                                                    selected - key.masterKeyId
                                                } else {
                                                    selected + key.masterKeyId
                                                }
                                            }
                                            .padding(vertical = 14.dp),
                                    )
                                    HorizontalDivider()
                                }
                            }
                            Button(
                                onClick = {
                                    val ids = selected.toLongArray()
                                    if (ids.isEmpty()) return@Button
                                    setResult(
                                        Activity.RESULT_OK,
                                        Intent().putExtra(OpenPgpConstants.EXTRA_KEY_IDS_SELECTED, ids),
                                    )
                                    finish()
                                },
                                enabled = selected.isNotEmpty(),
                                modifier = Modifier.fillMaxWidth().padding(vertical = 12.dp),
                            ) {
                                Text(stringResource(R.string.api_select_encrypt_key_confirm))
                            }
                        }
                    }
                }
            }
        }
    }

    companion object {
        const val EXTRA_CALLER_PACKAGE = "caller_package"

        private fun normalizeEmail(raw: String?): String? {
            if (raw.isNullOrBlank()) return null
            val trimmed = raw.trim()
            val angle = trimmed.substringAfter('<', missingDelimiterValue = "")
                .substringBefore('>', missingDelimiterValue = "")
            val candidate = (angle.ifBlank { trimmed }).trim().lowercase()
            return candidate.takeIf { it.contains('@') }
        }

        private fun uidMatchesAny(key: KeySummary, emails: Set<String>): Boolean {
            val uid = key.primaryUserId?.lowercase().orEmpty()
            if (uid.isEmpty()) return false
            return emails.any { email -> email in uid || uid.contains("<$email>") }
        }
    }
}
