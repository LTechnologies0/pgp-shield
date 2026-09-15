package ltechnologies.onionphone.pgpshield.ui.keys

/**
 * Compose UI and view model for the key detail screen, exposing identity,
 * subkey, export and management actions for a single key ring.
 */

import ltechnologies.onionphone.pgpshield.util.SensitiveClipboard
import android.content.Context
import android.content.Intent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.ui.Alignment
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.KeyDetail
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeySummary
import ltechnologies.onionphone.pgpshield.engine.AlgorithmLabels
import ltechnologies.onionphone.pgpshield.engine.PgpAlgorithmPolicy
import ltechnologies.onionphone.pgpshield.engine.PgpOperators
import ltechnologies.onionphone.pgpshield.engine.SubkeyType
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveScreenColumn
import ltechnologies.onionphone.pgpshield.ui.components.DestructiveConfirmDialog
import ltechnologies.onionphone.pgpshield.ui.components.FormBottomSheet
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffoldTopBarVariant
import ltechnologies.onionphone.pgpshield.ui.components.WindowLayout
import ltechnologies.onionphone.pgpshield.ui.components.AlgorithmChip
import ltechnologies.onionphone.pgpshield.ui.components.ChipRow
import ltechnologies.onionphone.pgpshield.ui.components.MonospaceScrollText
import ltechnologies.onionphone.pgpshield.ui.components.RevokedBadge
import ltechnologies.onionphone.pgpshield.ui.components.ExpiredBadge
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyDate
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyId
import ltechnologies.onionphone.pgpshield.ui.components.rememberAdaptiveMetrics
import ltechnologies.onionphone.pgpshield.util.SecureScreen
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * [androidx.lifecycle.ViewModel] providing read-only detail and export access
 * for a single key ring; all repository access happens on [Dispatchers.IO].
 */
@HiltViewModel
class KeyDetailViewModel @Inject constructor(
    private val keyRepository: KeyRepository,
) : androidx.lifecycle.ViewModel() {
    /** Loads the full [KeyDetail] for [keyId], or null if not found. */
    suspend fun loadDetail(keyId: Long): KeyDetail? = withContext(Dispatchers.IO) {
        keyRepository.getKeyDetail(keyId)
    }

    /** Returns the ASCII-armored public key for [keyId], or null if missing. */
    suspend fun exportPublic(keyId: Long): ByteArray? = withContext(Dispatchers.IO) {
        keyRepository.getArmoredPublic(keyId)
    }

    /** Returns the ASCII-armored secret key for [keyId], or null if missing. */
    suspend fun exportSecret(keyId: Long): ByteArray? = withContext(Dispatchers.IO) {
        keyRepository.getArmoredSecret(keyId)
    }
}

/**
 * Detail screen for a single key ring.
 *
 * Displays identity, subkey, export and management sections and hosts the sheets
 * and dialogs for revoke, passphrase change, subkey/user-id addition and
 * certification. Mutating actions are delegated to [listViewModel].
 *
 * @param keyId master key id of the key being displayed.
 * @param onBack invoked to navigate back.
 * @param listViewModel view model owning key mutation operations.
 * @param detailViewModel view model providing detail/export reads.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyDetailScreen(
    keyId: Long,
    onBack: () -> Unit,
    listViewModel: KeyListViewModel,
    detailViewModel: KeyDetailViewModel = hiltViewModel(),
) {
    val keys by listViewModel.keys.collectAsStateWithLifecycle()
    val opError by listViewModel.error.collectAsState()
    val opLoading by listViewModel.isLoading.collectAsState()
    val key = keys.find { it.masterKeyId == keyId }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val metrics = rememberAdaptiveMetrics()
    var detail by remember { mutableStateOf<KeyDetail?>(null) }
    var detailLoaded by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf<String?>(null) }
    var showDeleteDialog by remember { mutableStateOf(false) }
    var showSecretExportDialog by remember { mutableStateOf(false) }
    var showRevokeDialog by remember { mutableStateOf(false) }
    var showPassphraseDialog by remember { mutableStateOf(false) }
    var showAddSubkeyDialog by remember { mutableStateOf(false) }
    var showRevocationDialog by remember { mutableStateOf(false) }
    var showCertifyDialog by remember { mutableStateOf(false) }
    var showAddUserIdDialog by remember { mutableStateOf(false) }
    var showTrustMenu by remember { mutableStateOf(false) }
    var revokePassphrase by remember { mutableStateOf("") }
    var revokeReason by remember { mutableStateOf("") }
    var certifyPassphrase by remember { mutableStateOf("") }
    var certifyUserId by remember { mutableStateOf("") }
    var certifyCertifierId by remember { mutableStateOf<Long?>(null) }
    var addUserIdText by remember { mutableStateOf("") }
    var addUserIdPassphrase by remember { mutableStateOf("") }
    var oldPassphrase by remember { mutableStateOf("") }
    var newPassphrase by remember { mutableStateOf("") }

    DisposableEffect(Unit) {
        onDispose {
            revokePassphrase = ""
            certifyPassphrase = ""
            addUserIdPassphrase = ""
            oldPassphrase = ""
            newPassphrase = ""
        }
    }

    LaunchedEffect(keyId) {
        detailLoaded = false
        detail = detailViewModel.loadDetail(keyId)
        detailLoaded = true
    }

    LaunchedEffect(detailLoaded, detail, key) {
        if (detailLoaded && detail == null && key == null) {
            onBack()
        }
    }

    val summary = detail?.summary ?: key

    SecureScreen {
        ScreenScaffold(
            title = summary?.primaryUserId ?: stringResource(R.string.keys_title),
            showBack = true,
            onBack = onBack,
            topBarVariant = ScreenScaffoldTopBarVariant.CenterAligned,
        ) { padding ->
            if (summary == null) {
                Text(stringResource(R.string.common_unknown), modifier = Modifier.padding(padding).padding(16.dp))
                return@ScreenScaffold
            }
            AdaptiveScreenColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                metrics = metrics,
                constrainMaxWidth = false,
            ) {
                ChipRow(modifier = Modifier.padding(top = 4.dp)) {
                    AlgorithmChip(summary.primaryAlgorithm)
                    if (summary.isSecret) AlgorithmChip(stringResource(R.string.keys_secret))
                    if (summary.hardwareManagedPassphrase) AlgorithmChip(stringResource(R.string.key_detail_chip_strongbox))
                    if (summary.isRevoked) RevokedBadge()
                    if (summary.isExpired) ExpiredBadge()
                }

                val useSideBySide = metrics.isLandscape &&
                    metrics.layout >= WindowLayout.Expanded &&
                    metrics.useTwoPane

                if (useSideBySide) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(metrics.sectionSpacing),
                        verticalAlignment = Alignment.Top,
                    ) {
                        Column(
                            modifier = Modifier.weight(1f).fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(metrics.sectionSpacing),
                        ) {
                            KeyDetailIdentitySection(summary)
                            KeyDetailSubkeysSection(detail?.subkeys.orEmpty())
                        }
                        Column(
                            modifier = Modifier.weight(1f).fillMaxWidth(),
                            verticalArrangement = Arrangement.spacedBy(metrics.sectionSpacing),
                        ) {
                            KeyDetailExportSection(
                                isSecret = summary.isSecret,
                                hardwareManagedPassphrase = summary.hardwareManagedPassphrase,
                                onSharePublic = {
                                    scope.launch {
                                        val armored = detailViewModel.exportPublic(keyId)?.let { String(it, Charsets.UTF_8) }
                                        if (armored != null) shareText(context, armored, "public-key.asc")
                                        status = context.getString(
                                            if (armored != null) R.string.key_detail_status_public_shared
                                            else R.string.key_detail_status_export_failed,
                                        )
                                    }
                                },
                                onCopyPublic = {
                                    scope.launch {
                                        val armored = detailViewModel.exportPublic(keyId)?.let { String(it, Charsets.UTF_8) }
                                        if (armored != null) copyToClipboard(context, armored)
                                        status = context.getString(
                                            if (armored != null) R.string.key_detail_status_public_copied
                                            else R.string.key_detail_status_copy_failed,
                                        )
                                    }
                                },
                                onChangePassphrase = { showPassphraseDialog = true },
                                onExportSecret = { showSecretExportDialog = true },
                            )
                            KeyDetailManageSection(
                                summary = summary,
                                trustLevel = summary.trustLevel,
                                showTrustMenu = showTrustMenu,
                                onTrustMenuChange = { showTrustMenu = it },
                                onTrustSelect = { level ->
                                    listViewModel.setTrustLevel(keyId, level) {
                                        scope.launch {
                                            detail = detailViewModel.loadDetail(keyId)
                                            status = context.getString(
                                                R.string.keys_trust_set_fmt,
                                                trustLabel(context, level),
                                            )
                                        }
                                    }
                                    showTrustMenu = false
                                },
                                onAddSubkey = { showAddSubkeyDialog = true },
                                onAddUserId = { showAddUserIdDialog = true },
                                onExportRevocation = { showRevocationDialog = true },
                                onCertify = { showCertifyDialog = true },
                                onRefreshKeyserver = {
                                    listViewModel.refreshFromKeyserver(keyId) {
                                        scope.launch {
                                            detail = detailViewModel.loadDetail(keyId)
                                            status = context.getString(R.string.key_detail_status_refreshed)
                                        }
                                    }
                                },
                                onUploadPublic = {
                                    listViewModel.uploadPublicKey(keyId) {
                                        status = context.getString(R.string.key_detail_status_uploaded)
                                    }
                                },
                                onRevoke = { showRevokeDialog = true },
                                onDelete = { showDeleteDialog = true },
                            )
                        }
                    }
                } else {
                    Column(
                        modifier = Modifier.fillMaxWidth(),
                        verticalArrangement = Arrangement.spacedBy(metrics.sectionSpacing),
                    ) {
                        KeyDetailIdentitySection(summary)
                        KeyDetailSubkeysSection(detail?.subkeys.orEmpty())
                        KeyDetailExportSection(
                        isSecret = summary.isSecret,
                        hardwareManagedPassphrase = summary.hardwareManagedPassphrase,
                        onSharePublic = {
                            scope.launch {
                                val armored = detailViewModel.exportPublic(keyId)?.let { String(it, Charsets.UTF_8) }
                                if (armored != null) shareText(context, armored, "public-key.asc")
                                status = context.getString(
                                    if (armored != null) R.string.key_detail_status_public_shared
                                    else R.string.key_detail_status_export_failed,
                                )
                            }
                        },
                        onCopyPublic = {
                            scope.launch {
                                val armored = detailViewModel.exportPublic(keyId)?.let { String(it, Charsets.UTF_8) }
                                if (armored != null) copyToClipboard(context, armored)
                                status = context.getString(
                                    if (armored != null) R.string.key_detail_status_public_copied
                                    else R.string.key_detail_status_copy_failed,
                                )
                            }
                        },
                        onChangePassphrase = { showPassphraseDialog = true },
                        onExportSecret = { showSecretExportDialog = true },
                    )
                    KeyDetailManageSection(
                        summary = summary,
                        trustLevel = summary.trustLevel,
                        showTrustMenu = showTrustMenu,
                        onTrustMenuChange = { showTrustMenu = it },
                        onTrustSelect = { level ->
                            listViewModel.setTrustLevel(keyId, level) {
                                scope.launch {
                                    detail = detailViewModel.loadDetail(keyId)
                                    status = context.getString(
                                        R.string.keys_trust_set_fmt,
                                        trustLabel(context, level),
                                    )
                                }
                            }
                            showTrustMenu = false
                        },
                        onAddSubkey = { showAddSubkeyDialog = true },
                        onAddUserId = { showAddUserIdDialog = true },
                        onExportRevocation = { showRevocationDialog = true },
                        onCertify = { showCertifyDialog = true },
                        onRefreshKeyserver = {
                            listViewModel.refreshFromKeyserver(keyId) {
                                scope.launch {
                                    detail = detailViewModel.loadDetail(keyId)
                                    status = context.getString(R.string.key_detail_status_refreshed)
                                }
                            }
                        },
                        onUploadPublic = {
                            listViewModel.uploadPublicKey(keyId) {
                                status = context.getString(R.string.key_detail_status_uploaded)
                            }
                        },
                        onRevoke = { showRevokeDialog = true },
                        onDelete = { showDeleteDialog = true },
                    )
                    }
                }

                status?.let { Text(it, modifier = Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodySmall) }
                if (opLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.padding(top = 8.dp).size(24.dp),
                        strokeWidth = 2.dp,
                    )
                }
                opError?.let {
                    Text(
                        it,
                        modifier = Modifier.padding(top = 8.dp),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        }

        AddSubkeySheet(
            visible = showAddSubkeyDialog,
            masterAlgorithm = detail?.subkeys?.firstOrNull { it.keyId == keyId }?.algorithm
                ?: detail?.subkeys?.firstOrNull()?.algorithm
                ?: 0,
            onDismiss = { showAddSubkeyDialog = false },
            onConfirm = { subkeyType, rsaBits, passphrase, expirySeconds ->
                showAddSubkeyDialog = false
                listViewModel.clearError()
                listViewModel.addSubkey(keyId, passphrase, subkeyType, rsaBits, expirySeconds) {
                    scope.launch {
                        detail = detailViewModel.loadDetail(keyId)
                        status = context.getString(R.string.key_detail_status_subkey_added)
                    }
                }
            },
        )
        RevocationCertSheet(
            visible = showRevocationDialog,
            passphrase = revokePassphrase,
            onPassphraseChange = { revokePassphrase = it },
            reason = revokeReason,
            onReasonChange = { revokeReason = it },
            onDismiss = {
                revokePassphrase = ""
                revokeReason = ""
                showRevocationDialog = false
            },
            onConfirm = {
                val pass = revokePassphrase.toCharArray()
                revokePassphrase = ""
                val reason = revokeReason
                revokeReason = ""
                showRevocationDialog = false
                listViewModel.exportRevocationCert(keyId, pass, reason) { cert ->
                    scope.launch {
                        shareText(context, String(cert, Charsets.UTF_8), "revocation.asc")
                        status = context.getString(R.string.key_detail_status_revocation_exported)
                    }
                }
            },
        )
        CertifyKeySheet(
            visible = showCertifyDialog,
            keys = keys.filter { it.isSecret },
            targetUserIds = detail?.summary?.let { listOfNotNull(it.primaryUserId) } ?: emptyList(),
            certifierId = certifyCertifierId ?: keyId,
            onCertifierChange = { certifyCertifierId = it },
            userId = certifyUserId.ifBlank { summary?.primaryUserId ?: "" },
            onUserIdChange = { certifyUserId = it },
            passphrase = certifyPassphrase,
            onPassphraseChange = { certifyPassphrase = it },
            onDismiss = {
                certifyPassphrase = ""
                showCertifyDialog = false
            },
            onConfirm = {
                val pass = certifyPassphrase.toCharArray()
                certifyPassphrase = ""
                val certifier = certifyCertifierId ?: keyId
                val uid = certifyUserId.ifBlank { summary?.primaryUserId ?: "" }
                showCertifyDialog = false
                listViewModel.certifyKey(certifier, keyId, pass, uid) {
                    scope.launch {
                        detail = detailViewModel.loadDetail(keyId)
                        status = context.getString(R.string.key_detail_status_certified)
                    }
                }
            },
        )
        AddUserIdSheet(
            visible = showAddUserIdDialog,
            userId = addUserIdText,
            onUserIdChange = { addUserIdText = it },
            passphrase = addUserIdPassphrase,
            onPassphraseChange = { addUserIdPassphrase = it },
            onDismiss = {
                addUserIdPassphrase = ""
                addUserIdText = ""
                showAddUserIdDialog = false
            },
            onConfirm = {
                val pass = addUserIdPassphrase.toCharArray()
                val uid = addUserIdText.trim()
                addUserIdPassphrase = ""
                addUserIdText = ""
                showAddUserIdDialog = false
                listViewModel.addUserId(keyId, pass, uid) {
                    scope.launch {
                        detail = detailViewModel.loadDetail(keyId)
                        status = context.getString(R.string.key_detail_status_user_id_added)
                    }
                }
            },
        )
        ChangePassphraseSheet(
            visible = showPassphraseDialog,
            oldPassphrase = oldPassphrase,
            onOldPassphraseChange = { oldPassphrase = it },
            newPassphrase = newPassphrase,
            onNewPassphraseChange = { newPassphrase = it },
            onDismiss = {
                oldPassphrase = ""
                newPassphrase = ""
                showPassphraseDialog = false
            },
            onConfirm = {
                val old = oldPassphrase.toCharArray()
                val new = newPassphrase.toCharArray()
                oldPassphrase = ""
                newPassphrase = ""
                showPassphraseDialog = false
                listViewModel.changePassphrase(keyId, old, new) {
                    status = context.getString(R.string.key_detail_status_passphrase_changed)
                }
            },
        )
        DestructiveConfirmDialog(
            visible = showSecretExportDialog,
            title = stringResource(R.string.key_detail_export_secret_title),
            message = stringResource(R.string.key_detail_export_secret_message),
            confirmLabel = stringResource(R.string.common_export),
            onDismiss = { showSecretExportDialog = false },
            onConfirm = {
                showSecretExportDialog = false
                scope.launch {
                    val armored = detailViewModel.exportSecret(keyId)?.let { String(it, Charsets.UTF_8) }
                    if (armored != null) shareText(context, armored, "secret-key.asc")
                    status = context.getString(
                        if (armored != null) R.string.key_detail_status_secret_shared
                        else R.string.key_detail_status_export_failed,
                    )
                }
            },
        )
        DestructiveConfirmDialog(
            visible = showRevokeDialog,
            title = stringResource(R.string.key_detail_revoke_title),
            message = stringResource(R.string.key_detail_revoke_message),
            confirmLabel = stringResource(R.string.common_revoke),
            onDismiss = { showRevokeDialog = false },
            onConfirm = {
                showRevokeDialog = false
                listViewModel.clearError()
                listViewModel.revokeKey(keyId) {
                    scope.launch {
                        detail = detailViewModel.loadDetail(keyId)
                        status = context.getString(R.string.key_detail_status_revoked)
                    }
                }
            },
        )
        DestructiveConfirmDialog(
            visible = showDeleteDialog,
            title = stringResource(R.string.key_detail_delete_title),
            message = stringResource(R.string.key_detail_delete_message),
            confirmLabel = stringResource(R.string.common_delete),
            onDismiss = { showDeleteDialog = false },
            onConfirm = {
                showDeleteDialog = false
                listViewModel.deleteKey(keyId) { onBack() }
            },
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TrustLevelDropdown(
    trustLevel: Int,
    expanded: Boolean,
    onExpandedChange: (Boolean) -> Unit,
    onSelect: (Int) -> Unit,
) {
    val context = LocalContext.current
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = onExpandedChange,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    ) {
        OutlinedTextField(
            value = trustLabel(context, trustLevel),
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.key_detail_trust_level)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { onExpandedChange(false) }) {
            (0..3).forEach { level ->
                DropdownMenuItem(
                    text = { Text(trustLabel(context, level)) },
                    onClick = { onSelect(level) },
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ChangePassphraseSheet(
    visible: Boolean,
    oldPassphrase: String,
    onOldPassphraseChange: (String) -> Unit,
    newPassphrase: String,
    onNewPassphraseChange: (String) -> Unit,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    FormBottomSheet(
        visible = visible,
        title = stringResource(R.string.key_detail_change_passphrase_title),
        onDismiss = onDismiss,
        confirmLabel = stringResource(R.string.common_change),
        onConfirm = onConfirm,
    ) {
        OutlinedTextField(
            value = oldPassphrase,
            onValueChange = onOldPassphraseChange,
            label = { Text(stringResource(R.string.key_detail_current_passphrase)) },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        )
        OutlinedTextField(
            value = newPassphrase,
            onValueChange = onNewPassphraseChange,
            label = { Text(stringResource(R.string.key_detail_new_passphrase)) },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddUserIdSheet(
    visible: Boolean,
    userId: String,
    onUserIdChange: (String) -> Unit,
    passphrase: String,
    onPassphraseChange: (String) -> Unit,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    FormBottomSheet(
        visible = visible,
        title = stringResource(R.string.key_detail_add_user_id_title),
        onDismiss = onDismiss,
        confirmLabel = stringResource(R.string.common_add),
        onConfirm = onConfirm,
        confirmEnabled = userId.isNotBlank() && passphrase.isNotEmpty(),
    ) {
        OutlinedTextField(
            value = userId,
            onValueChange = onUserIdChange,
            label = { Text(stringResource(R.string.key_detail_user_id_label)) },
            placeholder = { Text(stringResource(R.string.create_key_user_id_label)) },
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        )
        OutlinedTextField(
            value = passphrase,
            onValueChange = onPassphraseChange,
            label = { Text(stringResource(R.string.intent_passphrase)) },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun RevocationCertSheet(
    visible: Boolean,
    passphrase: String,
    onPassphraseChange: (String) -> Unit,
    reason: String,
    onReasonChange: (String) -> Unit,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    FormBottomSheet(
        visible = visible,
        title = stringResource(R.string.key_detail_export_revocation_title),
        onDismiss = onDismiss,
        confirmLabel = stringResource(R.string.common_export),
        onConfirm = onConfirm,
    ) {
        OutlinedTextField(
            value = passphrase,
            onValueChange = onPassphraseChange,
            label = { Text(stringResource(R.string.intent_passphrase)) },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        )
        OutlinedTextField(
            value = reason,
            onValueChange = onReasonChange,
            label = { Text(stringResource(R.string.key_detail_reason_optional)) },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun CertifyKeySheet(
    visible: Boolean,
    keys: List<ltechnologies.onionphone.pgpshield.data.KeySummary>,
    targetUserIds: List<String>,
    certifierId: Long,
    onCertifierChange: (Long) -> Unit,
    userId: String,
    onUserIdChange: (String) -> Unit,
    passphrase: String,
    onPassphraseChange: (String) -> Unit,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    var certifierMenu by remember { mutableStateOf(false) }
    FormBottomSheet(
        visible = visible,
        title = stringResource(R.string.key_detail_certify_title),
        onDismiss = onDismiss,
        confirmLabel = stringResource(R.string.key_detail_certify_action),
        onConfirm = onConfirm,
        confirmEnabled = passphrase.isNotEmpty() && userId.isNotBlank(),
    ) {
        ExposedDropdownMenuBox(
            expanded = certifierMenu,
            onExpandedChange = { certifierMenu = it },
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        ) {
            val label = keys.find { it.masterKeyId == certifierId }?.primaryUserId
                ?: stringResource(R.string.key_detail_select_certifier)
            OutlinedTextField(
                value = label,
                onValueChange = {},
                readOnly = true,
                label = { Text(stringResource(R.string.key_detail_certifier_secret_key)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(certifierMenu) },
                modifier = Modifier.menuAnchor().fillMaxWidth(),
            )
            ExposedDropdownMenu(expanded = certifierMenu, onDismissRequest = { certifierMenu = false }) {
                keys.forEach { key ->
                    DropdownMenuItem(
                        text = { Text(key.primaryUserId ?: formatKeyId(key.masterKeyId)) },
                        onClick = {
                            onCertifierChange(key.masterKeyId)
                            certifierMenu = false
                        },
                    )
                }
            }
        }
        OutlinedTextField(
            value = userId,
            onValueChange = onUserIdChange,
            label = { Text(stringResource(R.string.key_detail_user_id_to_certify)) },
            placeholder = { Text(targetUserIds.firstOrNull() ?: "") },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        OutlinedTextField(
            value = passphrase,
            onValueChange = onPassphraseChange,
            label = { Text(stringResource(R.string.key_detail_certifier_passphrase)) },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddSubkeySheet(
    visible: Boolean,
    masterAlgorithm: Int,
    onDismiss: () -> Unit,
    onConfirm: (SubkeyType, Int, CharArray, Long) -> Unit,
) {
    val preferredTypes = remember(masterAlgorithm) {
        PgpAlgorithmPolicy.preferredSubkeyTypesForMaster(masterAlgorithm)
    }
    var subkeyType by remember(masterAlgorithm) {
        mutableStateOf(PgpAlgorithmPolicy.defaultSubkeyTypeForMaster(masterAlgorithm))
    }
    var rsaBits by remember { mutableIntStateOf(3072) }
    var passphrase by remember { mutableStateOf("") }
    var expiryYears by remember { mutableStateOf("") }
    var typeMenuExpanded by remember { mutableStateOf(false) }
    var rsaMenuExpanded by remember { mutableStateOf(false) }
    val needsRsa = subkeyType == SubkeyType.ENCRYPT_RSA ||
        subkeyType == SubkeyType.SIGN_RSA ||
        subkeyType == SubkeyType.AUTH_RSA

    FormBottomSheet(
        visible = visible,
        title = stringResource(R.string.key_detail_add_subkey_title),
        onDismiss = {
            passphrase = ""
            onDismiss()
        },
        confirmLabel = stringResource(R.string.common_add),
        onConfirm = {
            val pass = passphrase.toCharArray()
            passphrase = ""
            val years = expiryYears.toLongOrNull()
            val expirySeconds = if (years != null && years > 0) years * 365L * 24L * 3600L else 0L
            onConfirm(subkeyType, rsaBits, pass, expirySeconds)
        },
        confirmEnabled = passphrase.isNotEmpty(),
    ) {
        ExposedDropdownMenuBox(
            expanded = typeMenuExpanded,
            onExpandedChange = { typeMenuExpanded = it },
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        ) {
            OutlinedTextField(
                value = AlgorithmLabels.forSubkeyType(subkeyType),
                onValueChange = {},
                readOnly = true,
                label = { Text(stringResource(R.string.key_detail_subkey_type)) },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(typeMenuExpanded) },
                modifier = Modifier.menuAnchor().fillMaxWidth(),
            )
            ExposedDropdownMenu(
                expanded = typeMenuExpanded,
                onDismissRequest = { typeMenuExpanded = false },
            ) {
                preferredTypes.forEach { type ->
                    DropdownMenuItem(
                        text = { Text(AlgorithmLabels.forSubkeyType(type)) },
                        onClick = {
                            subkeyType = type
                            typeMenuExpanded = false
                        },
                    )
                }
            }
        }
        if (needsRsa) {
            ExposedDropdownMenuBox(
                expanded = rsaMenuExpanded,
                onExpandedChange = { rsaMenuExpanded = it },
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
            ) {
                OutlinedTextField(
                    value = stringResource(R.string.create_key_rsa_bits_fmt, rsaBits),
                    onValueChange = {},
                    readOnly = true,
                    label = { Text(stringResource(R.string.create_key_rsa_key_size)) },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(rsaMenuExpanded) },
                    modifier = Modifier.menuAnchor().fillMaxWidth(),
                )
                ExposedDropdownMenu(
                    expanded = rsaMenuExpanded,
                    onDismissRequest = { rsaMenuExpanded = false },
                ) {
                    PgpAlgorithmPolicy.allowedRsaBits.sorted().forEach { bits ->
                        DropdownMenuItem(
                            text = { Text(stringResource(R.string.create_key_rsa_bits_fmt, bits)) },
                            onClick = {
                                rsaBits = bits
                                rsaMenuExpanded = false
                            },
                        )
                    }
                }
            }
        }
        OutlinedTextField(
            value = passphrase,
            onValueChange = { passphrase = it },
            label = { Text(stringResource(R.string.intent_passphrase)) },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        OutlinedTextField(
            value = expiryYears,
            onValueChange = { expiryYears = it.filter { ch -> ch.isDigit() } },
            label = { Text(stringResource(R.string.create_key_expiry_years)) },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun KeyDetailSectionCard(
    title: String,
    content: @Composable ColumnScope.() -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
        ) {
            Text(
                title,
                style = MaterialTheme.typography.titleSmall,
                color = MaterialTheme.colorScheme.primary,
            )
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 8.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                content = content,
            )
        }
    }
}

@Composable
private fun KeyDetailIdentitySection(summary: ltechnologies.onionphone.pgpshield.data.KeySummary) {
    val context = LocalContext.current
    KeyDetailSectionCard(title = stringResource(R.string.key_detail_section_identity)) {
        Text(stringResource(R.string.key_detail_key_id_fmt, formatKeyId(summary.masterKeyId)))
        MonospaceScrollText(stringResource(R.string.key_detail_fingerprint_fmt, summary.fingerprint))
        Text(stringResource(R.string.key_detail_created_fmt, formatKeyDate(summary.createdAt)))
        Text(stringResource(R.string.key_detail_subkey_count_fmt, summary.subkeyCount))
        Text(stringResource(R.string.keys_trust_label_fmt, trustLabel(context, summary.trustLevel)))
    }
}

@Composable
private fun KeyDetailSubkeysSection(subkeys: List<ltechnologies.onionphone.pgpshield.engine.model.SubkeyInfo>) {
    if (subkeys.isEmpty()) return
    KeyDetailSectionCard(title = stringResource(R.string.key_detail_section_subkeys)) {
        subkeys.forEach { sub ->
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(vertical = 4.dp),
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(formatKeyId(sub.keyId), style = MaterialTheme.typography.titleSmall)
                Text(AlgorithmLabels.forAlgorithm(sub.algorithm), style = MaterialTheme.typography.bodySmall)
                Text(
                    PgpOperators.formatKeyFlags(sub.flags).joinToString(", "),
                    style = MaterialTheme.typography.labelSmall,
                )
                Text(
                    stringResource(R.string.keys_created_fmt, formatKeyDate(sub.creationTime.toEpochMilli())),
                    style = MaterialTheme.typography.labelSmall,
                )
                val exp = sub.expirationTime
                Text(
                    if (exp != null) {
                        stringResource(R.string.keys_expires_fmt, formatKeyDate(exp.toEpochMilli()))
                    } else {
                        stringResource(R.string.keys_no_expiry)
                    },
                    style = MaterialTheme.typography.labelSmall,
                )
                if (sub.isRevoked) RevokedBadge()
                if (exp != null && !exp.isAfter(java.time.Instant.now())) ExpiredBadge()
            }
        }
    }
}

@Composable
private fun KeyDetailExportSection(
    isSecret: Boolean,
    hardwareManagedPassphrase: Boolean,
    onSharePublic: () -> Unit,
    onCopyPublic: () -> Unit,
    onChangePassphrase: () -> Unit,
    onExportSecret: () -> Unit,
) {
    KeyDetailSectionCard(title = stringResource(R.string.key_detail_section_export)) {
        OutlinedButton(onClick = onSharePublic, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.key_detail_export_public_share))
        }
        OutlinedButton(onClick = onCopyPublic, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.key_detail_copy_public))
        }
        if (isSecret) {
            if (hardwareManagedPassphrase) {
                Text(
                    text = stringResource(R.string.key_detail_hardware_passphrase),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 8.dp),
                )
            } else {
                OutlinedButton(onClick = onChangePassphrase, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.key_detail_change_passphrase))
                }
                OutlinedButton(onClick = onExportSecret, modifier = Modifier.fillMaxWidth()) {
                    Text(stringResource(R.string.key_detail_export_secret))
                }
            }
        }
    }
}

@Composable
private fun KeyDetailManageSection(
    summary: ltechnologies.onionphone.pgpshield.data.KeySummary,
    trustLevel: Int,
    showTrustMenu: Boolean,
    onTrustMenuChange: (Boolean) -> Unit,
    onTrustSelect: (Int) -> Unit,
    onAddSubkey: () -> Unit,
    onAddUserId: () -> Unit,
    onExportRevocation: () -> Unit,
    onCertify: () -> Unit,
    onRefreshKeyserver: () -> Unit,
    onUploadPublic: () -> Unit,
    onRevoke: () -> Unit,
    onDelete: () -> Unit,
) {
    KeyDetailSectionCard(title = stringResource(R.string.key_detail_section_manage)) {
        if (summary.isSecret && !summary.isRevoked) {
            OutlinedButton(onClick = onAddSubkey, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.key_detail_add_subkey))
            }
            OutlinedButton(onClick = onAddUserId, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.key_detail_add_user_id))
            }
            OutlinedButton(onClick = onExportRevocation, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.key_detail_export_revocation))
            }
        }
        OutlinedButton(onClick = onCertify, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.key_detail_certify))
        }
        OutlinedButton(onClick = onRefreshKeyserver, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.key_detail_refresh_keyserver))
        }
        OutlinedButton(onClick = onUploadPublic, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.key_detail_upload_public))
        }
        TrustLevelDropdown(
            trustLevel = trustLevel,
            expanded = showTrustMenu,
            onExpandedChange = onTrustMenuChange,
            onSelect = onTrustSelect,
        )
        if (!summary.isRevoked) {
            OutlinedButton(onClick = onRevoke, modifier = Modifier.fillMaxWidth()) {
                Text(stringResource(R.string.keys_revoke))
            }
        }
        OutlinedButton(onClick = onDelete, modifier = Modifier.fillMaxWidth()) {
            Text(stringResource(R.string.keys_delete))
        }
    }
}

private fun trustLabel(context: Context, level: Int): String = context.getString(
    when (level) {
        KeySummary.TRUST_MARGINAL -> R.string.keys_trust_marginal
        KeySummary.TRUST_FULL -> R.string.keys_trust_full
        KeySummary.TRUST_NEVER -> R.string.keys_trust_never
        else -> R.string.keys_trust_unknown
    },
)

private fun copyToClipboard(context: Context, text: String) {
    SensitiveClipboard.copy(context, "pgp-key", text)
}

private fun shareText(context: Context, text: String, filename: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
        putExtra(Intent.EXTRA_SUBJECT, filename)
    }
    context.startActivity(Intent.createChooser(intent, context.getString(R.string.keys_share)))
}
