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
import androidx.compose.material3.Switch
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import androidx.fragment.app.FragmentActivity
import androidx.hilt.navigation.compose.hiltViewModel
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.engine.MessageCompression
import ltechnologies.onionphone.pgpshield.engine.MessageIntegrity
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
    var passphraseField by remember { mutableStateOf("") }
    var pkcs12PasswordField by remember { mutableStateOf("") }
    val secretKey = remember(keys, state.secretKeyId) {
        keys.find { it.masterKeyId == state.secretKeyId }
    }
    val secretKeys = remember(keys) { keys.filter { it.isSecret } }
    val context = LocalContext.current
    val metrics = rememberAdaptiveMetrics()
    val scope = rememberCoroutineScope()

    LaunchedEffect(context) {
        (context as? FragmentActivity)?.let { viewModel.bindHost(it) }
    }
    LaunchedEffect(state.sensitiveInputEpoch) {
        passphraseField = ""
        pkcs12PasswordField = ""
    }

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
                FormatPicker(
                    format = state.format,
                    onSelect = viewModel::setFormat,
                    enabled = mode == CryptoMode.ENCRYPT || mode == CryptoMode.DECRYPT,
                )
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
                                CryptoMode.ENCRYPT -> if (state.format == CryptoFormat.SMIME) {
                                    SmimeEncryptPanel(
                                        state = state,
                                        viewModel = viewModel,
                                        metrics = metrics,
                                        pkcs12Password = pkcs12PasswordField,
                                        onPkcs12PasswordChange = {
                                            pkcs12PasswordField = it
                                            viewModel.setSmimePkcs12Password(it)
                                        },
                                        onPickFile = { pickInputFile.launch(arrayOf("*/*")) },
                                        onPickPkcs12 = {
                                            pickInputFile.launch(arrayOf("application/x-pkcs12", "application/pkcs12", "*/*"))
                                        },
                                    )
                                } else {
                                    EncryptPanel(
                                        state = state,
                                        keys = keys,
                                        metrics = metrics,
                                        viewModel = viewModel,
                                        onPickFile = { pickInputFile.launch(arrayOf("*/*")) },
                                        onPickFolder = { pickMultipleFiles.launch(arrayOf("*/*")) },
                                    )
                                }
                                CryptoMode.DECRYPT -> if (state.format == CryptoFormat.SMIME) {
                                    SmimeDecryptPanel(
                                        state = state,
                                        viewModel = viewModel,
                                        metrics = metrics,
                                        onPickFile = { pickInputFile.launch(arrayOf("*/*", "application/pkcs7-mime")) },
                                    )
                                } else {
                                    DecryptPanel(
                                        state = state,
                                        secretKeys = secretKeys,
                                        secretKey = secretKey,
                                        secretMenu = secretMenu,
                                        onSecretMenuChange = { secretMenu = it },
                                        metrics = metrics,
                                        viewModel = viewModel,
                                        passphrase = passphraseField,
                                        onPassphraseChange = {
                                            passphraseField = it
                                            viewModel.setPassphrase(it)
                                        },
                                        onPickFile = { pickInputFile.launch(arrayOf("*/*")) },
                                    )
                                }
                                CryptoMode.SIGN -> SignPanel(
                                    state = state,
                                    secretKeys = secretKeys,
                                    secretKey = secretKey,
                                    secretMenu = secretMenu,
                                    onSecretMenuChange = { secretMenu = it },
                                    metrics = metrics,
                                    viewModel = viewModel,
                                    passphrase = passphraseField,
                                    onPassphraseChange = {
                                        passphraseField = it
                                        viewModel.setPassphrase(it)
                                    },
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


@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun FormatPicker(
    format: CryptoFormat,
    onSelect: (CryptoFormat) -> Unit,
    enabled: Boolean,
) {
    if (!enabled) return
    SingleChoiceSegmentedButtonRow(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 8.dp, vertical = 4.dp),
    ) {
        SegmentedButton(
            selected = format == CryptoFormat.OPENPGP,
            onClick = { onSelect(CryptoFormat.OPENPGP) },
            shape = SegmentedButtonDefaults.itemShape(index = 0, count = 2),
        ) { Text("OpenPGP") }
        SegmentedButton(
            selected = format == CryptoFormat.SMIME,
            onClick = { onSelect(CryptoFormat.SMIME) },
            shape = SegmentedButtonDefaults.itemShape(index = 1, count = 2),
        ) { Text(stringResource(R.string.crypto_smime_mode)) }
    }
}

@Composable
private fun SmimeEncryptPanel(
    state: CryptoUiState,
    viewModel: CryptoViewModel,
    metrics: ltechnologies.onionphone.pgpshield.ui.components.AdaptiveMetrics,
    pkcs12Password: String,
    onPkcs12PasswordChange: (String) -> Unit,
    onPickFile: () -> Unit,
    onPickPkcs12: () -> Unit,
) {
    Text(
        stringResource(R.string.crypto_smime_encrypt_hint),
        style = MaterialTheme.typography.bodySmall,
        modifier = Modifier.padding(top = 8.dp),
    )
    if (state.smimeIdentities.isEmpty()) {
        Text(
            stringResource(R.string.crypto_smime_no_certs),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.padding(top = 8.dp),
        )
    } else {
        state.smimeIdentities.forEach { id ->
            val selected = id.alias in state.smimeRecipientAliases
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 4.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = id.alias + " — " + id.certificate.subjectX500Principal.name,
                    style = MaterialTheme.typography.bodyMedium,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Switch(
                    checked = selected,
                    onCheckedChange = { checked ->
                        val next = if (checked) {
                            state.smimeRecipientAliases + id.alias
                        } else {
                            state.smimeRecipientAliases - id.alias
                        }
                        viewModel.setSmimeRecipientAliases(next)
                    },
                )
            }
        }
    }
    OutlinedTextField(
        value = pkcs12Password,
        onValueChange = onPkcs12PasswordChange,
        label = { Text(stringResource(R.string.crypto_smime_pkcs12_password)) },
        visualTransformation = PasswordVisualTransformation(),
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
        singleLine = true,
    )
    OutlinedButton(
        onClick = onPickPkcs12,
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 8.dp),
    ) { Text(stringResource(R.string.crypto_smime_import_pkcs12)) }
    val name = state.inputFileName
    if (state.inputFileBytes != null && name != null &&
        (name.endsWith(".p12", true) || name.endsWith(".pfx", true))
    ) {
        val pkcs12 = state.inputFileBytes
        Button(
            onClick = { if (pkcs12 != null) viewModel.importSmimePkcs12(pkcs12) },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp),
            enabled = !state.isBusy && pkcs12 != null,
        ) { Text(stringResource(R.string.crypto_smime_confirm_import)) }
    }
    if (state.payload == CryptoPayload.FILE) {
        FilePickRow(stringResource(R.string.crypto_no_file_selected), state.inputFileName, onPickFile)
        ActionButton(
            label = stringResource(R.string.crypto_encrypt_file_action),
            busy = state.isBusy,
            onClick = viewModel::encrypt,
            enabled = state.inputFileBytes != null && state.smimeRecipientAliases.isNotEmpty(),
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
                    label = { Text(stringResource(R.string.crypto_smime_cms_output)) },
                    modifier = Modifier.fillMaxWidth().adaptiveTextFieldHeight(metrics = metrics),
                )
            },
        )
        ActionButton(
            label = stringResource(R.string.crypto_encrypt_action),
            busy = state.isBusy,
            onClick = viewModel::encrypt,
            enabled = state.plaintext.isNotBlank() && state.smimeRecipientAliases.isNotEmpty(),
        )
    }
}

@Composable
private fun SmimeDecryptPanel(
    state: CryptoUiState,
    viewModel: CryptoViewModel,
    metrics: ltechnologies.onionphone.pgpshield.ui.components.AdaptiveMetrics,
    onPickFile: () -> Unit,
) {
    val withKeys = state.smimeIdentities.filter { it.privateKey != null }
    Text(
        stringResource(R.string.crypto_smime_decrypt_hint),
        style = MaterialTheme.typography.bodySmall,
        modifier = Modifier.padding(top = 8.dp),
    )
    withKeys.forEach { id ->
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 4.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(id.alias, modifier = Modifier.weight(1f))
            Switch(
                checked = state.smimeIdentityAlias == id.alias,
                onCheckedChange = { if (it) viewModel.selectSmimeIdentity(id.alias) },
            )
        }
    }
    if (state.payload == CryptoPayload.FILE) {
        FilePickRow(stringResource(R.string.crypto_no_file_selected), state.inputFileName, onPickFile)
        ActionButton(
            label = stringResource(R.string.crypto_decrypt_file_action),
            busy = state.isBusy,
            onClick = viewModel::decrypt,
            enabled = state.inputFileBytes != null && state.smimeIdentityAlias != null,
        )
    } else {
        AdaptiveTwoPane(
            metrics = metrics,
            modifier = Modifier.padding(top = 8.dp),
            start = {
                OutlinedTextField(
                    value = state.ciphertext,
                    onValueChange = viewModel::setCiphertext,
                    label = { Text(stringResource(R.string.crypto_smime_cms_input)) },
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
            enabled = state.ciphertext.isNotBlank() && state.smimeIdentityAlias != null,
        )
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
        keyFilter = { !it.isRevoked && it.trustLevel != KeySummary.TRUST_NEVER },
        modifier = Modifier.padding(top = 8.dp),
    )
    Text(
        stringResource(R.string.crypto_integrity_profile),
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.padding(top = 8.dp),
    )
    listOf(
        MessageIntegrity.SEIPD_V2_AEAD to "SEIPDv2 AEAD",
        MessageIntegrity.LIBREPGP_V5_AEAD to "LibrePGP v5 AEAD",
        MessageIntegrity.MDC to "MDC",
    ).forEach { (value, label) ->
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(label, style = MaterialTheme.typography.bodySmall)
            Switch(
                checked = state.messageIntegrity == value,
                onCheckedChange = { if (it) viewModel.setMessageIntegrity(value) },
            )
        }
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(top = 4.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text("Compress (ZLIB)", style = MaterialTheme.typography.bodyMedium)
        Switch(
            checked = state.messageCompression == MessageCompression.ZLIB,
            onCheckedChange = {
                viewModel.setMessageCompression(
                    if (it) MessageCompression.ZLIB else MessageCompression.NONE,
                )
            },
        )
    }
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
    passphrase: String,
    onPassphraseChange: (String) -> Unit,
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
    PassphraseOrHardwareHint(
        secretKey = secretKey,
        passphrase = passphrase,
        onPassphraseChange = onPassphraseChange,
    )
    if (state.payload == CryptoPayload.FILE) {
        FilePickRow(stringResource(R.string.crypto_pick_encrypted_file), state.inputFileName, onPickFile)
        ActionButton(
            label = stringResource(R.string.crypto_decrypt_file_action),
            busy = state.isBusy,
            onClick = viewModel::decrypt,
            enabled = state.inputFileBytes != null && state.secretKeyId != null,
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
            enabled = state.ciphertext.isNotBlank() && state.secretKeyId != null,
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
    passphrase: String,
    onPassphraseChange: (String) -> Unit,
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
    PassphraseOrHardwareHint(
        secretKey = secretKey,
        passphrase = passphrase,
        onPassphraseChange = onPassphraseChange,
    )
    if (state.payload == CryptoPayload.FILE) {
        FilePickRow(stringResource(R.string.crypto_pick_file_to_sign), state.inputFileName, onPickFile)
        ActionButton(
            label = stringResource(R.string.crypto_sign_file_action),
            busy = state.isBusy,
            onClick = viewModel::sign,
            enabled = state.inputFileBytes != null && state.secretKeyId != null,
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
            enabled = state.plaintext.isNotBlank() && state.secretKeyId != null,
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
private fun PassphraseOrHardwareHint(
    secretKey: KeySummary?,
    passphrase: String,
    onPassphraseChange: (String) -> Unit,
) {
    if (secretKey?.hardwareManagedPassphrase == true) {
        Text(
            text = stringResource(R.string.crypto_hardware_passphrase_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
    } else {
        PassphraseField(passphrase, onPassphraseChange)
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
