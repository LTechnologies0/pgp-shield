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
import androidx.compose.ui.Alignment
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Button
import androidx.compose.material3.Card
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

    LaunchedEffect(keyId) {
        detailLoaded = false
        detail = detailViewModel.loadDetail(keyId)
        detailLoaded = true
        // #region agent log
        ltechnologies.onionphone.pgpshield.util.DebugAgentLog.log(
            location = "KeyDetailScreen.kt:LaunchedEffect",
            message = "detail loaded",
            data = mapOf(
                "keyId" to keyId,
                "foundInList" to (key != null),
                "detailLoaded" to (detail != null),
            ),
            hypothesisId = "C",
        )
        // #endregion
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
                    if (summary.isSecret) AlgorithmChip("Secret")
                    if (summary.isRevoked) RevokedBadge()
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
                                onSharePublic = {
                                    scope.launch {
                                        val armored = detailViewModel.exportPublic(keyId)?.let { String(it, Charsets.UTF_8) }
                                        if (armored != null) shareText(context, armored, "public-key.asc")
                                        status = if (armored != null) "Public key shared" else "Export failed"
                                    }
                                },
                                onCopyPublic = {
                                    scope.launch {
                                        val armored = detailViewModel.exportPublic(keyId)?.let { String(it, Charsets.UTF_8) }
                                        if (armored != null) copyToClipboard(context, armored)
                                        status = if (armored != null) "Public key copied" else "Copy failed"
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
                                    listViewModel.setTrustLevel(keyId, level)
                                    showTrustMenu = false
                                    status = "Trust set to ${trustLabel(level)}"
                                },
                                onAddSubkey = { showAddSubkeyDialog = true },
                                onAddUserId = { showAddUserIdDialog = true },
                                onExportRevocation = { showRevocationDialog = true },
                                onCertify = { showCertifyDialog = true },
                                onRefreshKeyserver = {
                                    listViewModel.refreshFromKeyserver(keyId) {
                                        scope.launch {
                                            detail = detailViewModel.loadDetail(keyId)
                                            status = "Refreshed from keyserver"
                                        }
                                    }
                                },
                                onUploadPublic = {
                                    listViewModel.uploadPublicKey(keyId) {
                                        status = "Public key uploaded — verify email on keys.openpgp.org if search by address is needed"
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
                        onSharePublic = {
                            scope.launch {
                                val armored = detailViewModel.exportPublic(keyId)?.let { String(it, Charsets.UTF_8) }
                                if (armored != null) shareText(context, armored, "public-key.asc")
                                status = if (armored != null) "Public key shared" else "Export failed"
                            }
                        },
                        onCopyPublic = {
                            scope.launch {
                                val armored = detailViewModel.exportPublic(keyId)?.let { String(it, Charsets.UTF_8) }
                                if (armored != null) copyToClipboard(context, armored)
                                status = if (armored != null) "Public key copied" else "Copy failed"
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
                            listViewModel.setTrustLevel(keyId, level)
                            showTrustMenu = false
                            status = "Trust set to ${trustLabel(level)}"
                        },
                        onAddSubkey = { showAddSubkeyDialog = true },
                        onAddUserId = { showAddUserIdDialog = true },
                        onExportRevocation = { showRevocationDialog = true },
                        onCertify = { showCertifyDialog = true },
                        onRefreshKeyserver = {
                            listViewModel.refreshFromKeyserver(keyId) {
                                scope.launch {
                                    detail = detailViewModel.loadDetail(keyId)
                                    status = "Refreshed from keyserver"
                                }
                            }
                        },
                        onUploadPublic = {
                            listViewModel.uploadPublicKey(keyId) {
                                status = "Public key uploaded — verify email on keys.openpgp.org if search by address is needed"
                            }
                        },
                        onRevoke = { showRevokeDialog = true },
                        onDelete = { showDeleteDialog = true },
                    )
                    }
                }

                status?.let { Text(it, modifier = Modifier.padding(top = 8.dp), style = MaterialTheme.typography.bodySmall) }
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
            onDismiss = { showAddSubkeyDialog = false },
            onConfirm = { subkeyType, rsaBits, passphrase ->
                showAddSubkeyDialog = false
                listViewModel.clearError()
                listViewModel.addSubkey(keyId, passphrase, subkeyType, rsaBits) {
                    scope.launch {
                        detail = detailViewModel.loadDetail(keyId)
                        status = "Subkey added"
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
                        status = "Revocation cert exported"
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
                        status = "Key certified"
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
                        status = "User ID added"
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
                    status = "Passphrase changed"
                }
            },
        )
        DestructiveConfirmDialog(
            visible = showSecretExportDialog,
            title = "Export secret key?",
            message = "This includes private key material. Only share with trusted apps.",
            confirmLabel = "Export",
            onDismiss = { showSecretExportDialog = false },
            onConfirm = {
                showSecretExportDialog = false
                scope.launch {
                    val armored = detailViewModel.exportSecret(keyId)?.let { String(it, Charsets.UTF_8) }
                    if (armored != null) shareText(context, armored, "secret-key.asc")
                    status = if (armored != null) "Secret key shared" else "Export failed"
                }
            },
        )
        DestructiveConfirmDialog(
            visible = showRevokeDialog,
            title = "Revoke key?",
            message = "Marks the key revoked in PGP Shield. Does not publish a revocation certificate.",
            confirmLabel = "Revoke",
            onDismiss = { showRevokeDialog = false },
            onConfirm = {
                listViewModel.revokeKey(keyId)
                showRevokeDialog = false
                status = "Key marked revoked"
            },
        )
        DestructiveConfirmDialog(
            visible = showDeleteDialog,
            title = "Delete key?",
            message = "Removes the key from this device. This cannot be undone.",
            confirmLabel = "Delete",
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
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = onExpandedChange,
        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
    ) {
        OutlinedTextField(
            value = trustLabel(trustLevel),
            onValueChange = {},
            readOnly = true,
            label = { Text("Trust level") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { onExpandedChange(false) }) {
            (0..3).forEach { level ->
                DropdownMenuItem(
                    text = { Text(trustLabel(level)) },
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
        title = "Change passphrase",
        onDismiss = onDismiss,
        confirmLabel = "Change",
        onConfirm = onConfirm,
    ) {
        OutlinedTextField(
            value = oldPassphrase,
            onValueChange = onOldPassphraseChange,
            label = { Text("Current passphrase") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        )
        OutlinedTextField(
            value = newPassphrase,
            onValueChange = onNewPassphraseChange,
            label = { Text("New passphrase") },
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
        title = "Add user ID",
        onDismiss = onDismiss,
        confirmLabel = "Add",
        onConfirm = onConfirm,
        confirmEnabled = userId.isNotBlank() && passphrase.isNotEmpty(),
    ) {
        OutlinedTextField(
            value = userId,
            onValueChange = onUserIdChange,
            label = { Text("User ID") },
            placeholder = { Text("Name <email@example.com>") },
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        )
        OutlinedTextField(
            value = passphrase,
            onValueChange = onPassphraseChange,
            label = { Text("Passphrase") },
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
        title = "Export revocation certificate",
        onDismiss = onDismiss,
        confirmLabel = "Export",
        onConfirm = onConfirm,
    ) {
        OutlinedTextField(
            value = passphrase,
            onValueChange = onPassphraseChange,
            label = { Text("Passphrase") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        )
        OutlinedTextField(
            value = reason,
            onValueChange = onReasonChange,
            label = { Text("Reason (optional)") },
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
        title = "Certify key",
        onDismiss = onDismiss,
        confirmLabel = "Certify",
        onConfirm = onConfirm,
        confirmEnabled = passphrase.isNotEmpty() && userId.isNotBlank(),
    ) {
        ExposedDropdownMenuBox(
            expanded = certifierMenu,
            onExpandedChange = { certifierMenu = it },
            modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
        ) {
            val label = keys.find { it.masterKeyId == certifierId }?.primaryUserId ?: "Select certifier"
            OutlinedTextField(
                value = label,
                onValueChange = {},
                readOnly = true,
                label = { Text("Certifier secret key") },
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
            label = { Text("User ID to certify") },
            placeholder = { Text(targetUserIds.firstOrNull() ?: "") },
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
        OutlinedTextField(
            value = passphrase,
            onValueChange = onPassphraseChange,
            label = { Text("Certifier passphrase") },
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
        )
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AddSubkeySheet(
    visible: Boolean,
    onDismiss: () -> Unit,
    onConfirm: (SubkeyType, Int, CharArray) -> Unit,
) {
    var subkeyType by remember { mutableStateOf(SubkeyType.ENCRYPT_CV25519) }
    var rsaBits by remember { mutableIntStateOf(3072) }
    var passphrase by remember { mutableStateOf("") }
    var typeMenuExpanded by remember { mutableStateOf(false) }
    var rsaMenuExpanded by remember { mutableStateOf(false) }
    val needsRsa = subkeyType == SubkeyType.ENCRYPT_RSA || subkeyType == SubkeyType.SIGN_RSA

    FormBottomSheet(
        visible = visible,
        title = "Add subkey",
        onDismiss = {
            passphrase = ""
            onDismiss()
        },
        confirmLabel = "Add",
        onConfirm = {
            val pass = passphrase.toCharArray()
            passphrase = ""
            onConfirm(subkeyType, rsaBits, pass)
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
                label = { Text("Subkey type") },
                trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(typeMenuExpanded) },
                modifier = Modifier.menuAnchor().fillMaxWidth(),
            )
            ExposedDropdownMenu(
                expanded = typeMenuExpanded,
                onDismissRequest = { typeMenuExpanded = false },
            ) {
                PgpAlgorithmPolicy.androidGeneratableSubkeyTypes.forEach { type ->
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
                    value = "RSA $rsaBits",
                    onValueChange = {},
                    readOnly = true,
                    label = { Text("RSA key size") },
                    trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(rsaMenuExpanded) },
                    modifier = Modifier.menuAnchor().fillMaxWidth(),
                )
                ExposedDropdownMenu(
                    expanded = rsaMenuExpanded,
                    onDismissRequest = { rsaMenuExpanded = false },
                ) {
                    PgpAlgorithmPolicy.allowedRsaBits.sorted().forEach { bits ->
                        DropdownMenuItem(
                            text = { Text("RSA $bits") },
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
            label = { Text("Passphrase") },
            visualTransformation = PasswordVisualTransformation(),
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
    KeyDetailSectionCard(title = "Identity") {
        Text("Key ID: ${formatKeyId(summary.masterKeyId)}")
        MonospaceScrollText("Fingerprint: ${summary.fingerprint}")
        Text("Created: ${formatKeyDate(summary.createdAt)}")
        Text("Subkeys: ${summary.subkeyCount}")
        Text("Trust: ${trustLabel(summary.trustLevel)}")
    }
}

@Composable
private fun KeyDetailSubkeysSection(subkeys: List<ltechnologies.onionphone.pgpshield.engine.model.SubkeyInfo>) {
    if (subkeys.isEmpty()) return
    KeyDetailSectionCard(title = "Subkeys") {
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
                    "Created ${formatKeyDate(sub.creationTime.toEpochMilli())}",
                    style = MaterialTheme.typography.labelSmall,
                )
                if (sub.isRevoked) RevokedBadge()
            }
        }
    }
}

@Composable
private fun KeyDetailExportSection(
    isSecret: Boolean,
    onSharePublic: () -> Unit,
    onCopyPublic: () -> Unit,
    onChangePassphrase: () -> Unit,
    onExportSecret: () -> Unit,
) {
    KeyDetailSectionCard(title = "Export") {
        OutlinedButton(onClick = onSharePublic, modifier = Modifier.fillMaxWidth()) {
            Text("Export public key (share)")
        }
        OutlinedButton(onClick = onCopyPublic, modifier = Modifier.fillMaxWidth()) {
            Text("Copy public key")
        }
        if (isSecret) {
            OutlinedButton(onClick = onChangePassphrase, modifier = Modifier.fillMaxWidth()) {
                Text("Change passphrase…")
            }
            OutlinedButton(onClick = onExportSecret, modifier = Modifier.fillMaxWidth()) {
                Text("Export secret key…")
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
    KeyDetailSectionCard(title = "Manage") {
        if (summary.isSecret && !summary.isRevoked) {
            OutlinedButton(onClick = onAddSubkey, modifier = Modifier.fillMaxWidth()) {
                Text("Add subkey…")
            }
            OutlinedButton(onClick = onAddUserId, modifier = Modifier.fillMaxWidth()) {
                Text("Add user ID…")
            }
            OutlinedButton(onClick = onExportRevocation, modifier = Modifier.fillMaxWidth()) {
                Text("Export revocation cert…")
            }
        }
        OutlinedButton(onClick = onCertify, modifier = Modifier.fillMaxWidth()) {
            Text("Certify key…")
        }
        OutlinedButton(onClick = onRefreshKeyserver, modifier = Modifier.fillMaxWidth()) {
            Text("Refresh from keyserver")
        }
        OutlinedButton(onClick = onUploadPublic, modifier = Modifier.fillMaxWidth()) {
            Text("Upload public key")
        }
        TrustLevelDropdown(
            trustLevel = trustLevel,
            expanded = showTrustMenu,
            onExpandedChange = onTrustMenuChange,
            onSelect = onTrustSelect,
        )
        if (!summary.isRevoked) {
            OutlinedButton(onClick = onRevoke, modifier = Modifier.fillMaxWidth()) {
                Text("Revoke key")
            }
        }
        OutlinedButton(onClick = onDelete, modifier = Modifier.fillMaxWidth()) {
            Text("Delete key")
        }
    }
}

private fun trustLabel(level: Int): String = when (level) {
    1 -> "Marginal"
    2 -> "Full"
    3 -> "Never"
    else -> "Unknown"
}

private fun copyToClipboard(context: Context, text: String) {
    SensitiveClipboard.copy(context, "pgp-key", text)
}

private fun shareText(context: Context, text: String, filename: String) {
    val intent = Intent(Intent.ACTION_SEND).apply {
        type = "text/plain"
        putExtra(Intent.EXTRA_TEXT, text)
        putExtra(Intent.EXTRA_SUBJECT, filename)
    }
    context.startActivity(Intent.createChooser(intent, "Share key"))
}
