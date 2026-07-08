package ltechnologies.onionphone.pgpshield.ui.keys

/**
 * Compose UI for importing OpenPGP keys by pasting armored text or picking a
 * key file, with automatic public/secret detection.
 */

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Column
import androidx.compose.ui.platform.LocalContext
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import ltechnologies.onionphone.pgpshield.data.ImportGuard
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveContentWidth
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.adaptiveTextFieldHeight
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveTwoPane
import ltechnologies.onionphone.pgpshield.ui.components.rememberAdaptiveMetrics
import androidx.compose.runtime.rememberCoroutineScope
import ltechnologies.onionphone.pgpshield.intent.IntentIoHelper
import ltechnologies.onionphone.pgpshield.util.ArmoredKeyDetector
import ltechnologies.onionphone.pgpshield.util.SecureScreen
import kotlinx.coroutines.launch

/**
 * Key import screen.
 *
 * Accepts pasted armored key text or a selected file, detects whether the block
 * is public or secret, and delegates the import to [viewModel].
 *
 * @param onBack invoked to navigate back.
 * @param viewModel backing [KeyListViewModel] (defaults to a Hilt instance).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ImportKeyScreen(
    onBack: () -> Unit,
    viewModel: KeyListViewModel = hiltViewModel(),
) {
    var armored by remember { mutableStateOf("") }
    var isSecret by remember { mutableStateOf(false) }
    var detected: Boolean? by remember { mutableStateOf(null) }
    val error by viewModel.error.collectAsState()
    val loading by viewModel.isLoading.collectAsState()
    val metrics = rememberAdaptiveMetrics()

    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            try {
                val bytes = IntentIoHelper.readUriBytes(context, uri)
                val text = String(bytes, Charsets.UTF_8)
                if (text.contains("BEGIN PGP")) {
                    armored = text
                    viewModel.clearError()
                }
            } catch (e: Exception) {
                viewModel.reportError(e.message ?: context.getString(R.string.import_file_read_failed))
            }
        }
    }

    LaunchedEffect(armored) {
        detected = ArmoredKeyDetector.isSecretBlock(armored)
        detected?.let { isSecret = it }
    }

    SecureScreen {
        ScreenScaffold(
            title = stringResource(R.string.keys_import_title),
            showBack = true,
            onBack = onBack,
        ) { padding ->
            AdaptiveContentWidth(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            ) {
                Column(Modifier.fillMaxSize()) {
                    Text(
                        stringResource(R.string.keys_import_desc),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    Text(
                        ArmoredKeyDetector.label(armored),
                        style = MaterialTheme.typography.labelMedium,
                        color = when (detected) {
                            true -> MaterialTheme.colorScheme.tertiary
                            false -> MaterialTheme.colorScheme.primary
                            null -> MaterialTheme.colorScheme.onSurfaceVariant
                        },
                        modifier = Modifier.padding(top = 4.dp),
                    )
                    AdaptiveTwoPane(
                        metrics = metrics,
                        modifier = Modifier
                            .weight(1f)
                            .padding(top = 8.dp),
                        start = {
                            OutlinedTextField(
                                value = armored,
                                onValueChange = { armored = it; viewModel.clearError() },
                                label = { Text(stringResource(R.string.keys_import_armor_label)) },
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .adaptiveTextFieldHeight(minLines = 10, metrics = metrics),
                            )
                        },
                        end = {
                            Column(
                                modifier = Modifier.fillMaxWidth(),
                                horizontalAlignment = Alignment.CenterHorizontally,
                            ) {
                                Text(stringResource(R.string.keys_import_contains_private))
                                Switch(
                                    checked = isSecret,
                                    onCheckedChange = { isSecret = it },
                                    enabled = detected == null,
                                )
                                if (detected != null) {
                                    Text(
                                        stringResource(R.string.keys_import_autodetected),
                                        style = MaterialTheme.typography.labelSmall,
                                    )
                                }
                            }
                        },
                    )
                    error?.let {
                        Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(bottom = 8.dp))
                    }
                    Button(
                        onClick = { filePicker.launch("*/*") },
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !loading,
                    ) { Text(stringResource(R.string.keys_import_from_file)) }
                    Button(
                        onClick = {
                            if (armored.contains("BEGIN PGP")) {
                                viewModel.importArmored(armored, isSecret, onBack)
                            }
                        },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        enabled = !loading && armored.contains("BEGIN PGP") &&
                            armored.toByteArray(Charsets.UTF_8).size <= ImportGuard.MAX_ARMORED_BYTES,
                    ) {
                        if (loading) {
                            CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                        }
                        Text(if (isSecret) stringResource(R.string.keys_import_secret) else stringResource(R.string.keys_import_public))
                    }
                }
            }
        }
    }
}
