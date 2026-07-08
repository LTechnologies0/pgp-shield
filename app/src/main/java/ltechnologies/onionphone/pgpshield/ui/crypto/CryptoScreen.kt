package ltechnologies.onionphone.pgpshield.ui.crypto

/**
 * Compose UI for the encrypt/decrypt/sign/verify screen, including per-mode
 * panels and text/file/folder payload handling.
 */

import ltechnologies.onionphone.pgpshield.util.SensitiveClipboard
import android.content.Intent
import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AttachFile
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Share
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import androidx.hilt.navigation.compose.hiltViewModel
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.KeySummary
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveContentWidth
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveTwoPane
import ltechnologies.onionphone.pgpshield.ui.components.KeyMultiSelectField
import ltechnologies.onionphone.pgpshield.ui.components.KeySelectDropdown
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.adaptiveTextFieldHeight
import ltechnologies.onionphone.pgpshield.ui.components.formatKeySummaryLine
import ltechnologies.onionphone.pgpshield.ui.components.rememberAdaptiveMetrics
import androidx.compose.runtime.rememberCoroutineScope
import ltechnologies.onionphone.pgpshield.intent.IntentIoHelper
import ltechnologies.onionphone.pgpshield.util.SecureScreen
import kotlinx.coroutines.launch

/** The selectable operation modes of the crypto screen. */
enum class CryptoMode { ENCRYPT, DECRYPT, SIGN, VERIFY }

/**
 * Top-level crypto screen composable.
 *
 * Renders the mode tabs, payload picker and the mode-specific panel, wiring user
 * actions to [CryptoViewModel] and handling file-picker and share intents.
 *
 * @param onBack invoked when the back affordance is used.
 * @param showBack whether to display the back affordance.
 * @param viewModel the backing [CryptoViewModel] (defaults to a Hilt instance).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CryptoScreen(
    onBack: () -> Unit = {},
    showBack: Boolean = true,
    viewModel: CryptoViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val keys by viewModel.keys.collectAsStateWithLifecycle()
    var secretMenu by remember { mutableStateOf(false) }
    var mode by rememberSaveable { mutableStateOf(CryptoMode.ENCRYPT) }
    val secretKey = remember(keys, state.secretKeyId) {
        keys.find { it.masterKeyId == state.secretKeyId }
    }
    val secretKeys = remember(keys) { keys.filter { it.isSecret } }
    val context = LocalContext.current
    val metrics = rememberAdaptiveMetrics()
    val scope = rememberCoroutineScope()

    val pickInputFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            IntentIoHelper.readUriNamed(context, uri)?.let { (name, bytes) ->
                viewModel.setInputFile(name, bytes)
            }
        }
    }
    val pickMultipleFiles = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (uris.isNullOrEmpty()) return@rememberLauncherForActivityResult
        scope.launch {
            val files = uris.mapNotNull { uri -> IntentIoHelper.readUriNamed(context, uri) }
            if (files.isNotEmpty()) viewModel.setFolderFiles(files)
        }
    }
    val pickSignatureFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri == null) return@rememberLauncherForActivityResult
        scope.launch {
            IntentIoHelper.readUriNamed(context, uri)?.let { (name, bytes) ->
                viewModel.setSignatureFile(name, bytes)
            }
        }
    }

    SecureScreen {
        ScreenScaffold(
            title = stringResource(R.string.crypto_title),
            showBack = showBack,
            onBack = onBack,
            actions = {
                if (state.payload == CryptoPayload.TEXT && state.output.isNotBlank()) {
                    IconButton(onClick = { copyToClipboard(context, state.output) }) {
                        Icon(Icons.Default.ContentCopy, contentDescription = stringResource(R.string.common_copy))
                    }
                    IconButton(onClick = { shareText(context, state.output) }) {
                        Icon(Icons.Default.Share, contentDescription = stringResource(R.string.common_share))
                    }
                }
                if (state.outputFileBytes != null && state.outputFileName != null) {
                    state.outputFileBytes?.let { bytes ->
                        state.outputFileName?.let { name ->
                            IconButton(onClick = {
                                scope.launch {
                                    CryptoFileHelper.shareBytes(context, bytes, name, "application/octet-stream")
                                }
                            }) {
                                Icon(Icons.Default.Share, contentDescription = stringResource(R.string.crypto_share_file))
                            }
                        }
                    }
                }
            },
        ) { padding ->
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            ) {
                if (keys.isEmpty()) {
                    AdaptiveContentWidth(modifier = Modifier.fillMaxWidth()) {
                        Text(
                            stringResource(R.string.crypto_no_keys),
                            style = MaterialTheme.typography.bodyMedium,
                            modifier = Modifier.padding(horizontal = metrics.horizontalPadding),
                        )
                    }
                    return@Column
                }
                PrimaryTabRow(selectedTabIndex = mode.ordinal) {
                    CryptoMode.entries.forEach { tab ->
                        Tab(
                            selected = mode == tab,
                            onClick = {
                                mode = tab
                                viewModel.onModeChanged(tab)
                            },
                            text = {
                                Text(
                                    when (tab) {
                                        CryptoMode.ENCRYPT -> stringResource(R.string.crypto_tab_encrypt)
                                        CryptoMode.DECRYPT -> stringResource(R.string.crypto_tab_decrypt)
                                        CryptoMode.SIGN -> stringResource(R.string.crypto_tab_sign)
                                        CryptoMode.VERIFY -> stringResource(R.string.crypto_tab_verify)
                                    },
                                )
                            },
                        )
                    }
                }
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .verticalScroll(rememberScrollState()),
                ) {
                    AdaptiveContentWidth(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.fillMaxWidth().padding(bottom = 16.dp)) {
                            PayloadTypePicker(
                                mode = mode,
                                payload = state.payload,
                                onSelect = viewModel::setPayload,
                            )
                            when (mode) {
                                CryptoMode.ENCRYPT -> EncryptPanel(
                                    state = state,
                                    keys = keys,
                                    metrics = metrics,
                                    viewModel = viewModel,
                                    onPickFile = { pickInputFile.launch(arrayOf("*/*")) },
                                    onPickFolder = { pickMultipleFiles.launch(arrayOf("*/*")) },
                                )
                                CryptoMode.DECRYPT -> DecryptPanel(
                                    state = state,
                                    secretKeys = secretKeys,
                                    secretKey = secretKey,
                                    secretMenu = secretMenu,
                                    onSecretMenuChange = { secretMenu = it },
                                    metrics = metrics,
                                    viewModel = viewModel,
                                    onPickFile = { pickInputFile.launch(arrayOf("*/*")) },
                                )
                                CryptoMode.SIGN -> SignPanel(
                                    state = state,
                                    secretKeys = secretKeys,
                                    secretKey = secretKey,
                                    secretMenu = secretMenu,
                                    onSecretMenuChange = { secretMenu = it },
                                    metrics = metrics,
                                    viewModel = viewModel,
                                    onPickFile = { pickInputFile.launch(arrayOf("*/*")) },
                                )
                                CryptoMode.VERIFY -> VerifyPanel(
                                    state = state,
                                    metrics = metrics,
                                    viewModel = viewModel,
                                    onPickDataFile = { pickInputFile.launch(arrayOf("*/*")) },
                                    onPickSigFile = {
                                        pickSignatureFile.launch(arrayOf("*/*", "application/pgp-signature"))
                                    },
                                )
                            }
                            state.fileStatus?.let {
                                Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
                            }
                            state.error?.let {
                                Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                            }
                        }
                    }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class, ExperimentalMaterial3Api::class)
@Composable
private fun PayloadTypePicker(mode: CryptoMode, payload: CryptoPayload, onSelect: (CryptoPayload) -> Unit) {
    val options = remember(mode) {
        buildList {
            add(CryptoPayload.TEXT)
            add(CryptoPayload.FILE)
            if (mode == CryptoMode.ENCRYPT) add(CryptoPayload.FOLDER)
        }
    }
    if (options.size <= 3) {
        SingleChoiceSegmentedButtonRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
        ) {
            options.forEachIndexed { index, type ->
                SegmentedButton(
                    selected = payload == type,
                    onClick = { onSelect(type) },
                    shape = SegmentedButtonDefaults.itemShape(index = index, count = options.size),
                ) {
                    Text(
                        when (type) {
                            CryptoPayload.TEXT -> stringResource(R.string.crypto_payload_text)
                            CryptoPayload.FILE -> stringResource(R.string.crypto_payload_file)
                            CryptoPayload.FOLDER -> stringResource(R.string.crypto_payload_folder)
                        },
                    )
                }
            }
        }
    }
}

@Composable
private fun FilePickRow(label: String, fileName: String?, onPick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(onClick = onPick, modifier = Modifier.weight(1f)) {
            Icon(Icons.Default.AttachFile, contentDescription = stringResource(R.string.crypto_attach_file), modifier = Modifier.padding(end = 8.dp))
            Text(stringResource(R.string.crypto_pick_file))
        }
    }
    Text(
        fileName ?: label,
        style = MaterialTheme.typography.bodySmall,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
        modifier = Modifier.padding(top = 4.dp),
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun EncryptPanel(
    state: CryptoUiState,
    keys: List<KeySummary>,
    metrics: ltechnologies.onionphone.pgpshield.ui.components.AdaptiveMetrics,
    viewModel: CryptoViewModel,
    onPickFile: () -> Unit,
    onPickFolder: () -> Unit,
) {
    Text(
        when (state.payload) {
            CryptoPayload.FILE -> stringResource(R.string.crypto_encrypt_file_hint)
            CryptoPayload.FOLDER -> stringResource(R.string.crypto_encrypt_folder_hint)
            CryptoPayload.TEXT -> stringResource(R.string.crypto_encrypt_text_hint)
        },
        style = MaterialTheme.typography.bodySmall,
        modifier = Modifier.padding(top = 8.dp),
    )
    KeyMultiSelectField(
        label = stringResource(R.string.crypto_recipient_keys),
        keys = keys,
        selectedIds = state.recipientKeyIds,
        onSelectionChange = viewModel::setRecipientKeyIds,
        keyFilter = { !it.isRevoked },
        modifier = Modifier.padding(top = 8.dp),
    )
    if (state.payload == CryptoPayload.FILE) {
        FilePickRow(stringResource(R.string.crypto_no_file_selected), state.inputFileName, onPickFile)
        ActionButton(
            label = stringResource(R.string.crypto_encrypt_file_action),
            busy = state.isBusy,
            onClick = viewModel::encrypt,
            enabled = state.inputFileBytes != null && state.recipientKeyIds.isNotEmpty(),
        )
    } else if (state.payload == CryptoPayload.FOLDER) {
        FilePickRow(
            stringResource(R.string.crypto_no_files_selected),
            state.folderFiles.firstOrNull()?.first?.let { "${state.folderFiles.size} files" },
            onPickFolder,
        )
        ActionButton(
            label = stringResource(R.string.crypto_encrypt_folder_action),
            busy = state.isBusy,
            onClick = viewModel::encrypt,
            enabled = state.folderFiles.isNotEmpty() && state.recipientKeyIds.isNotEmpty(),
        )
    } else {
        AdaptiveTwoPane(
            metrics = metrics,
            modifier = Modifier.padding(top = 8.dp),
            start = {
                OutlinedTextField(
                    value = state.plaintext,
                    onValueChange = viewModel::setPlaintext,
                    label = { Text(stringResource(R.string.crypto_plaintext)) },
                    modifier = Modifier.fillMaxWidth().adaptiveTextFieldHeight(metrics = metrics),
                )
            },
            end = {
                OutlinedTextField(
                    value = state.output,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text(stringResource(R.string.crypto_armored_ciphertext)) },
                    modifier = Modifier.fillMaxWidth().adaptiveTextFieldHeight(metrics = metrics),
                )
            },
        )
        ActionButton(
            label = stringResource(R.string.crypto_encrypt_action),
            busy = state.isBusy,
            onClick = viewModel::encrypt,
            enabled = state.plaintext.isNotBlank() && state.recipientKeyIds.isNotEmpty(),
        )
    }
}

@Composable
private fun DecryptPanel(
    state: CryptoUiState,
    secretKeys: List<KeySummary>,
    secretKey: KeySummary?,
    secretMenu: Boolean,
    onSecretMenuChange: (Boolean) -> Unit,
    metrics: ltechnologies.onionphone.pgpshield.ui.components.AdaptiveMetrics,
    viewModel: CryptoViewModel,
    onPickFile: () -> Unit,
) {
    if (secretKeys.isEmpty()) {
        Text(stringResource(R.string.crypto_no_secret_keys), color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
        return
    }
    KeySelectDropdown(
        label = stringResource(R.string.crypto_your_secret_key),
        keys = secretKeys,
        selectedId = secretKey?.masterKeyId,
        onSelect = { id -> id?.let { viewModel.selectSecretKey(it) } },
        expanded = secretMenu,
        onExpandedChange = onSecretMenuChange,
        emptyLabel = stringResource(R.string.common_select_key),
        lineFormatter = ::formatKeySummaryLine,
        modifier = Modifier.padding(top = 8.dp),
    )
    PassphraseField(state.passphrase, viewModel::setPassphrase)
    if (state.payload == CryptoPayload.FILE) {
        FilePickRow(stringResource(R.string.crypto_pick_encrypted_file), state.inputFileName, onPickFile)
        ActionButton(
            label = stringResource(R.string.crypto_decrypt_file_action),
            busy = state.isBusy,
            onClick = viewModel::decrypt,
            enabled = state.inputFileBytes != null && state.secretKeyId != null && state.passphrase.isNotBlank(),
        )
        FileOutputRow(state.outputFileName, state.outputFileBytes)
    } else {
        AdaptiveTwoPane(
            metrics = metrics,
            modifier = Modifier.padding(top = 8.dp),
            start = {
                OutlinedTextField(
                    value = state.ciphertext,
                    onValueChange = viewModel::setCiphertext,
                    label = { Text(stringResource(R.string.crypto_armored_ciphertext)) },
                    modifier = Modifier.fillMaxWidth().adaptiveTextFieldHeight(metrics = metrics),
                )
            },
            end = {
                OutlinedTextField(
                    value = state.plaintext,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text(stringResource(R.string.crypto_plaintext)) },
                    modifier = Modifier.fillMaxWidth().adaptiveTextFieldHeight(metrics = metrics),
                )
            },
        )
        ActionButton(
            label = stringResource(R.string.crypto_decrypt_action),
            busy = state.isBusy,
            onClick = viewModel::decrypt,
            enabled = state.ciphertext.isNotBlank() && state.secretKeyId != null && state.passphrase.isNotBlank(),
        )
    }
}

@Composable
private fun SignPanel(
    state: CryptoUiState,
    secretKeys: List<KeySummary>,
    secretKey: KeySummary?,
    secretMenu: Boolean,
    onSecretMenuChange: (Boolean) -> Unit,
    metrics: ltechnologies.onionphone.pgpshield.ui.components.AdaptiveMetrics,
    viewModel: CryptoViewModel,
    onPickFile: () -> Unit,
) {
    if (secretKeys.isEmpty()) {
        Text(stringResource(R.string.crypto_no_secret_keys), color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
        return
    }
    KeySelectDropdown(
        label = stringResource(R.string.crypto_your_secret_key),
        keys = secretKeys,
        selectedId = secretKey?.masterKeyId,
        onSelect = { id -> id?.let { viewModel.selectSecretKey(it) } },
        expanded = secretMenu,
        onExpandedChange = onSecretMenuChange,
        emptyLabel = stringResource(R.string.common_select_key),
        lineFormatter = ::formatKeySummaryLine,
        modifier = Modifier.padding(top = 8.dp),
    )
    PassphraseField(state.passphrase, viewModel::setPassphrase)
    if (state.payload == CryptoPayload.FILE) {
        FilePickRow(stringResource(R.string.crypto_pick_file_to_sign), state.inputFileName, onPickFile)
        ActionButton(
            label = stringResource(R.string.crypto_sign_file_action),
            busy = state.isBusy,
            onClick = viewModel::sign,
            enabled = state.inputFileBytes != null && state.secretKeyId != null && state.passphrase.isNotBlank(),
        )
        FileOutputRow(state.outputFileName, state.outputFileBytes)
    } else {
        AdaptiveTwoPane(
            metrics = metrics,
            modifier = Modifier.padding(top = 8.dp),
            start = {
                OutlinedTextField(
                    value = state.plaintext,
                    onValueChange = viewModel::setPlaintext,
                    label = { Text(stringResource(R.string.crypto_message_to_sign)) },
                    modifier = Modifier.fillMaxWidth().adaptiveTextFieldHeight(metrics = metrics),
                )
            },
            end = {
                OutlinedTextField(
                    value = state.output,
                    onValueChange = {},
                    readOnly = true,
                    label = { Text(stringResource(R.string.crypto_signed_message)) },
                    modifier = Modifier.fillMaxWidth().adaptiveTextFieldHeight(metrics = metrics),
                )
            },
        )
        ActionButton(
            label = stringResource(R.string.crypto_sign_message_action),
            busy = state.isBusy,
            onClick = viewModel::sign,
            enabled = state.plaintext.isNotBlank() && state.secretKeyId != null && state.passphrase.isNotBlank(),
        )
    }
}

@Composable
private fun VerifyPanel(
    state: CryptoUiState,
    metrics: ltechnologies.onionphone.pgpshield.ui.components.AdaptiveMetrics,
    viewModel: CryptoViewModel,
    onPickDataFile: () -> Unit,
    onPickSigFile: () -> Unit,
) {
    if (state.payload == CryptoPayload.FILE) {
        Text(
            stringResource(R.string.crypto_verify_detached_hint),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp),
        )
        FilePickRow(stringResource(R.string.crypto_original_file), state.inputFileName, onPickDataFile)
        FilePickRow(stringResource(R.string.crypto_signature_file), state.signatureFileName, onPickSigFile)
    } else {
        Text(
            stringResource(R.string.crypto_paste_cleartext_signed),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 8.dp),
        )
        OutlinedTextField(
            value = state.signedInput,
            onValueChange = viewModel::setSignedInput,
            label = { Text(stringResource(R.string.crypto_signed_message)) },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp)
                .adaptiveTextFieldHeight(minLines = 6, metrics = metrics),
        )
    }
    state.verifyResult?.let { result ->
        val color = if (result.valid) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.error
        Text(
            if (result.valid) stringResource(R.string.crypto_valid_signature) else stringResource(R.string.crypto_invalid_signature),
            color = color,
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = 8.dp),
        )
        result.signerLabel?.let { Text(stringResource(R.string.crypto_signer_fmt, it), style = MaterialTheme.typography.bodyMedium) }
        result.error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
    }
    ActionButton(
        label = if (state.payload == CryptoPayload.FILE) stringResource(R.string.crypto_verify_file_action) else stringResource(R.string.crypto_verify_action),
        busy = state.isBusy,
        onClick = viewModel::verify,
        enabled = if (state.payload == CryptoPayload.FILE) {
            state.inputFileBytes != null && state.signatureFileBytes != null
        } else {
            state.signedInput.contains("BEGIN PGP")
        },
    )
}

@Composable
private fun FileOutputRow(fileName: String?, fileBytes: ByteArray?) {
    if (fileName == null || fileBytes == null) return
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(
            onClick = {
                scope.launch {
                    CryptoFileHelper.shareBytes(context, fileBytes, fileName, "application/octet-stream")
                }
            },
            modifier = Modifier.weight(1f),
        ) {
            Icon(Icons.Default.Share, contentDescription = stringResource(R.string.common_share), modifier = Modifier.padding(end = 8.dp))
            Text(stringResource(R.string.crypto_share_filename_fmt, fileName))
        }
    }
}

@Composable
private fun PassphraseField(value: String, onValueChange: (String) -> Unit) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(stringResource(R.string.crypto_key_passphrase)) },
        visualTransformation = PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions.Default,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    )
}

@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
private fun ActionButton(label: String, busy: Boolean, onClick: () -> Unit, enabled: Boolean) {
    Button(
        onClick = onClick,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        enabled = enabled && !busy,
    ) {
        if (busy) {
            LoadingIndicator(modifier = Modifier.padding(end = 8.dp))
        }
        Text(label)
    }
}

private fun copyToClipboard(context: android.content.Context, text: String) {
    SensitiveClipboard.copy(context, "pgp-output", text)
}

private fun shareText(context: android.content.Context, text: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
    }
    context.startActivity(Intent.createChooser(intent, context.getString(R.string.common_share)))
}
