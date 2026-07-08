package ltechnologies.onionphone.pgpshield.ui.overlay

/**
 * Compose UI section embedded in settings for configuring per-app overlay
 * behaviour, encoding, padding templates and automation modes.
 */

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.db.OverlayAppConfigEntity
import ltechnologies.onionphone.pgpshield.encoding.EncodingMethod
import ltechnologies.onionphone.pgpshield.encoding.EncodingRegistry
import ltechnologies.onionphone.pgpshield.ui.components.KeyMultiSelectField
import ltechnologies.onionphone.pgpshield.ui.components.KeySelectDropdown
import ltechnologies.onionphone.pgpshield.ui.components.M3ListCard
import ltechnologies.onionphone.pgpshield.ui.components.SectionHeader
import ltechnologies.onionphone.pgpshield.ui.components.SettingSwitchRow
import ltechnologies.onionphone.pgpshield.ui.components.StringSelectDropdown
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyId

private enum class OverlayAutoMode { MANUAL, SUGGEST, AUTO_SEND }

/**
 * Overlay configuration section for the settings screen.
 *
 * Lists existing per-app configs and provides a form to create or edit one,
 * including recipient keys, encoding method, padding and automation options.
 *
 * @param viewModel backing [OverlayConfigViewModel].
 * @param modifier optional layout modifier.
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class, ExperimentalLayoutApi::class)
@Composable
fun OverlayConfigSection(
    viewModel: OverlayConfigViewModel,
    modifier: Modifier = Modifier,
) {
    val configs by viewModel.configs.collectAsStateWithLifecycle()
    val keys by viewModel.keys.collectAsStateWithLifecycle()
    val templates by viewModel.paddingTemplates.collectAsStateWithLifecycle()
    val installedApps by viewModel.installedApps.collectAsStateWithLifecycle()
    var packageName by remember { mutableStateOf("") }
    var recipientKeyIds by remember { mutableStateOf<Set<Long>>(emptySet()) }
    var encoding by remember { mutableStateOf(EncodingMethod.ZERO_WIDTH) }
    var enabled by remember { mutableStateOf(true) }
    var decryptKeyId by remember { mutableStateOf<Long?>(null) }
    var paddingTemplateId by remember { mutableStateOf<String?>(null) }
    var overlayTextSizeSp by remember { mutableStateOf(14f) }
    var overlayAlpha by remember { mutableStateOf(0.95f) }
    var minDecoyChars by remember { mutableStateOf(20) }
    var composeViaClipboard by remember { mutableStateOf(false) }
    var autoMode by remember { mutableStateOf(OverlayAutoMode.MANUAL) }
    var showResultToast by remember { mutableStateOf(true) }
    var requireConfirmBeforeSetText by remember { mutableStateOf(false) }
    var appMenuExpanded by remember { mutableStateOf(false) }
    var decryptMenuExpanded by remember { mutableStateOf(false) }
    var paddingMenuExpanded by remember { mutableStateOf(false) }

    LaunchedEffect(appMenuExpanded) {
        if (appMenuExpanded) viewModel.ensureInstalledAppsLoaded()
    }

    Column(modifier = modifier) {
        Text(
            stringResource(R.string.overlay_apps_subtitle),
            style = MaterialTheme.typography.bodyMedium,
        )
        Text(
            stringResource(R.string.onboarding_step_3),
            style = MaterialTheme.typography.bodySmall,
            modifier = Modifier.padding(top = 4.dp),
        )
        OutlinedTextField(
            value = packageName,
            onValueChange = { packageName = it },
            label = { Text(stringResource(R.string.overlay_package_name)) },
            placeholder = { Text("com.telegram.messenger") },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 8.dp),
        )
        if (installedApps.isNotEmpty()) {
            StringSelectDropdown(
                label = stringResource(R.string.overlay_installed_apps),
                value = stringResource(R.string.overlay_pick_installed_app),
                options = installedApps.take(100).map { it.packageName to "${it.label} (${it.packageName})" },
                onSelect = { pkg ->
                    packageName = pkg
                    appMenuExpanded = false
                },
                expanded = appMenuExpanded,
                onExpandedChange = { appMenuExpanded = it },
                modifier = Modifier.padding(vertical = 4.dp),
            )
        }
        SectionHeader(stringResource(R.string.overlay_styling_section))
        Text(stringResource(R.string.overlay_text_size_fmt, overlayTextSizeSp.toInt()), style = MaterialTheme.typography.bodySmall)
        Slider(
            value = overlayTextSizeSp,
            onValueChange = { overlayTextSizeSp = it },
            valueRange = 10f..20f,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(stringResource(R.string.overlay_alpha_fmt, overlayAlpha), style = MaterialTheme.typography.bodySmall)
        Slider(
            value = overlayAlpha,
            onValueChange = { overlayAlpha = it },
            valueRange = 0.5f..1f,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(stringResource(R.string.overlay_min_decoy_fmt, minDecoyChars), style = MaterialTheme.typography.bodySmall)
        Slider(
            value = minDecoyChars.toFloat(),
            onValueChange = { minDecoyChars = it.toInt() },
            valueRange = 0f..80f,
            steps = 16,
            modifier = Modifier.fillMaxWidth(),
        )
        SettingSwitchRow(
            label = stringResource(R.string.overlay_compose_clipboard),
            checked = composeViaClipboard,
            onChecked = { composeViaClipboard = it },
        )
        SettingSwitchRow(
            label = stringResource(R.string.overlay_show_result_toast),
            checked = showResultToast,
            onChecked = { showResultToast = it },
        )
        SettingSwitchRow(
            label = stringResource(R.string.overlay_confirm_before_set_text),
            checked = requireConfirmBeforeSetText,
            onChecked = { requireConfirmBeforeSetText = it },
        )
        SectionHeader(stringResource(R.string.overlay_automation_section))
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            OverlayAutoMode.entries.forEachIndexed { index, mode ->
                SegmentedButton(
                    selected = autoMode == mode,
                    onClick = { autoMode = mode },
                    shape = SegmentedButtonDefaults.itemShape(index = index, count = OverlayAutoMode.entries.size),
                ) {
                    Text(
                        when (mode) {
                            OverlayAutoMode.MANUAL -> stringResource(R.string.overlay_auto_manual)
                            OverlayAutoMode.SUGGEST -> stringResource(R.string.overlay_auto_suggest)
                            OverlayAutoMode.AUTO_SEND -> stringResource(R.string.overlay_auto_send)
                        },
                    )
                }
            }
        }
        SectionHeader(stringResource(R.string.overlay_encoding_section))
        val encodingOptions = EncodingMethod.entries
        if (encodingOptions.size <= 4) {
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                encodingOptions.forEachIndexed { index, method ->
                    SegmentedButton(
                        selected = encoding == method,
                        onClick = { encoding = method },
                        shape = SegmentedButtonDefaults.itemShape(index = index, count = encodingOptions.size),
                    ) {
                        Text(EncodingRegistry.toId(method))
                    }
                }
            }
        } else {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                encodingOptions.forEach { method ->
                    FilterChip(
                        selected = encoding == method,
                        onClick = { encoding = method },
                        label = { Text(EncodingRegistry.toId(method)) },
                    )
                }
            }
        }
        if (encoding == EncodingMethod.GPG || encoding == EncodingMethod.SYMMETRIC) {
            KeyMultiSelectField(
                label = stringResource(R.string.overlay_encrypt_with_recipient),
                keys = keys,
                selectedIds = recipientKeyIds,
                onSelectionChange = { recipientKeyIds = it },
                modifier = Modifier.padding(vertical = 4.dp),
            )
            KeySelectDropdown(
                label = stringResource(R.string.overlay_decrypt_with_secret),
                keys = keys,
                selectedId = decryptKeyId,
                onSelect = { decryptKeyId = it },
                keyFilter = { it.isSecret },
                expanded = decryptMenuExpanded,
                onExpandedChange = { decryptMenuExpanded = it },
                modifier = Modifier.padding(vertical = 4.dp),
            )
        }
        if (encoding == EncodingMethod.PADDING && templates.isNotEmpty()) {
            val templateOptions = templates.map { it.templateId to it.title }
            val templateLabel = templateOptions.firstOrNull { it.first == (paddingTemplateId ?: templates.first().templateId) }?.second
                ?: stringResource(R.string.overlay_template)
            StringSelectDropdown(
                label = stringResource(R.string.overlay_padding_template),
                value = templateLabel,
                options = templateOptions,
                onSelect = { paddingTemplateId = it },
                expanded = paddingMenuExpanded,
                onExpandedChange = { paddingMenuExpanded = it },
                modifier = Modifier.padding(vertical = 4.dp),
            )
        }
        Text(stringResource(R.string.overlay_enabled_for_app), modifier = Modifier.padding(top = 8.dp))
        Switch(checked = enabled, onCheckedChange = { enabled = it })
        Button(
            onClick = {
                if (packageName.isNotBlank()) {
                    val recipientList = recipientKeyIds.toList()
                    viewModel.save(
                        OverlayAppConfigEntity(
                            packageName = packageName.trim(),
                            encodingMethod = EncodingRegistry.toId(encoding),
                            recipientKeyIds = recipientList.drop(1).joinToString(",") { formatKeyId(it) },
                            decryptKeyId = decryptKeyId,
                            encryptKeyId = recipientList.firstOrNull(),
                            paddingTemplateId = paddingTemplateId ?: templates.firstOrNull()?.templateId,
                            enabled = enabled,
                            overlayTextSizeSp = overlayTextSizeSp,
                            overlayAlpha = overlayAlpha,
                            minDecoyChars = minDecoyChars,
                            composeViaClipboard = composeViaClipboard,
                            autoMode = when (autoMode) {
                                OverlayAutoMode.MANUAL -> "manual"
                                OverlayAutoMode.SUGGEST -> "suggest"
                                OverlayAutoMode.AUTO_SEND -> "auto_send"
                            },
                            showResultToast = showResultToast,
                            requireConfirmBeforeSetText = requireConfirmBeforeSetText,
                        ),
                    )
                    packageName = ""
                    recipientKeyIds = emptySet()
                    decryptKeyId = null
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 12.dp),
            enabled = packageName.isNotBlank(),
        ) { Text(stringResource(R.string.common_save)) }
        SectionHeader(stringResource(R.string.overlay_configured_apps))
        configs.forEach { cfg ->
            M3ListCard(onClick = null, modifier = Modifier.padding(vertical = 4.dp)) {
                Column(Modifier.padding(12.dp)) {
                    Text(cfg.packageName, style = MaterialTheme.typography.titleSmall)
                    Text("${cfg.encodingMethod} · enabled=${cfg.enabled}")
                    Text("mode=${cfg.autoMode}", style = MaterialTheme.typography.bodySmall)
                    cfg.encryptKeyId?.let { Text("Encrypt: ${formatKeyId(it)}", style = MaterialTheme.typography.bodySmall) }
                    cfg.decryptKeyId?.let { Text("Decrypt: ${formatKeyId(it)}", style = MaterialTheme.typography.bodySmall) }
                    IconButton(onClick = { viewModel.delete(cfg.packageName) }) {
                        Icon(Icons.Default.Delete, contentDescription = stringResource(R.string.common_remove))
                    }
                }
            }
        }
    }
}
