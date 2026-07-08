package ltechnologies.onionphone.pgpshield.ui.settings

/**
 * Compose UI for the settings screen: defaults, keyserver, overlay, API access,
 * privacy and accessibility options.
 */

import android.content.Intent
import android.provider.Settings
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ElevatedCard
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLifecycleOwner
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.overlay.ShieldAccessibilityService
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveScreenColumn
import ltechnologies.onionphone.pgpshield.ui.components.KeySelectDropdown
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.SectionHeader
import ltechnologies.onionphone.pgpshield.ui.components.SettingSwitchRow
import ltechnologies.onionphone.pgpshield.ui.components.StringSelectDropdown
import ltechnologies.onionphone.pgpshield.ui.overlay.OverlayConfigSection
import ltechnologies.onionphone.pgpshield.ui.overlay.OverlayConfigViewModel
import ltechnologies.onionphone.pgpshield.util.AccessibilityHelper
import ltechnologies.onionphone.pgpshield.util.SecureScreen

/**
 * Settings screen composable.
 *
 * Renders grouped preference sections and embeds [OverlayConfigSection] when
 * the tab is active. Refreshes accessibility state on resume.
 *
 * @param onBack invoked to navigate back.
 * @param onOpenQrKeys invoked to open the QR key exchange screen.
 * @param onOpenSmartCard invoked to open the smart-card screen.
 * @param showBack whether to display the back affordance.
 * @param isActive whether this tab is currently visible (defers overlay config load).
 * @param viewModel backing [SettingsViewModel].
 * @param overlayViewModel backing [OverlayConfigViewModel].
 */
@Composable
fun SettingsScreen(
    onBack: () -> Unit,
    onOpenQrKeys: () -> Unit = {},
    onOpenSmartCard: () -> Unit = {},
    showBack: Boolean = true,
    isActive: Boolean = true,
    viewModel: SettingsViewModel = hiltViewModel(),
    overlayViewModel: OverlayConfigViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var showOverlayConfig by remember { mutableStateOf(false) }
    if (isActive && !showOverlayConfig) {
        LaunchedEffect(Unit) { showOverlayConfig = true }
    }
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle

    DisposableEffect(lifecycle) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME) {
                viewModel.refreshAccessibility(
                    AccessibilityHelper.isServiceEnabled(context, ShieldAccessibilityService::class.java),
                )
            }
        }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer) }
    }

    SecureScreen {
        ScreenScaffold(
            title = stringResource(R.string.settings_title),
            showBack = showBack,
            onBack = onBack,
        ) { padding ->
            AdaptiveScreenColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            ) {
                SectionHeader(stringResource(R.string.settings_security))
                ElevatedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                ) {
                    Column(Modifier.padding(vertical = 8.dp)) {
                        KeySelectDropdown(
                            label = stringResource(R.string.settings_default_encrypt_key),
                            keys = state.keys,
                            selectedId = state.settings.defaultEncryptKeyId,
                            onSelect = viewModel::setDefaultEncryptKey,
                            allowAuto = true,
                            emptyLabel = stringResource(R.string.settings_auto_first_available),
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                        )
                        KeySelectDropdown(
                            label = stringResource(R.string.settings_default_sign_key),
                            keys = state.keys,
                            selectedId = state.settings.defaultSignKeyId,
                            onSelect = viewModel::setDefaultSignKey,
                            allowAuto = true,
                            emptyLabel = stringResource(R.string.settings_auto_first_available),
                            keyFilter = { it.isSecret },
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                        )
                    }
                }

                SectionHeader(stringResource(R.string.settings_keys))
                ElevatedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                ) {
                    Column(Modifier.padding(vertical = 4.dp)) {
                        SettingSwitchRow(
                            label = stringResource(R.string.settings_keyserver_lookup),
                            subtitle = stringResource(R.string.settings_keyserver_lookup_subtitle),
                            checked = state.settings.keyserverLookupEnabled,
                            onChecked = viewModel::setKeyserverLookup,
                        )
                        OutlinedTextField(
                            value = state.settings.keyserverUrl,
                            onValueChange = viewModel::setKeyserverUrl,
                            label = { Text(stringResource(R.string.settings_keyserver_url)) },
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 4.dp),
                        )
                        SettingSwitchRow(
                            label = stringResource(R.string.settings_show_fingerprint),
                            checked = state.settings.showFingerprintOnList,
                            onChecked = viewModel::setShowFingerprint,
                        )
                        SettingSwitchRow(
                            label = stringResource(R.string.settings_backup_reminder),
                            checked = state.settings.backupReminderEnabled,
                            onChecked = viewModel::setBackupReminder,
                        )
                        SettingSwitchRow(
                            label = stringResource(R.string.settings_allow_screenshots),
                            subtitle = stringResource(R.string.settings_allow_screenshots_subtitle),
                            checked = state.settings.allowScreenshots,
                            onChecked = viewModel::setAllowScreenshots,
                        )
                        SettingSwitchRow(
                            label = stringResource(R.string.settings_autocrypt),
                            subtitle = stringResource(R.string.settings_autocrypt_subtitle),
                            checked = state.settings.autocryptEnabled,
                            onChecked = viewModel::setAutocrypt,
                        )
                        val languageOptions = listOf(
                            "system" to stringResource(R.string.settings_language_system),
                            "en" to stringResource(R.string.settings_language_en),
                            "fr" to stringResource(R.string.settings_language_fr),
                            "es" to stringResource(R.string.settings_language_es),
                        )
                        val languageLabel = languageOptions.find { it.first == state.settings.appLanguage }?.second
                            ?: stringResource(R.string.settings_language_system)
                        StringSelectDropdown(
                            label = stringResource(R.string.settings_language),
                            value = languageLabel,
                            options = languageOptions,
                            onSelect = viewModel::setAppLanguage,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                        )
                        OutlinedButton(
                            onClick = viewModel::refreshAllKeys,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                        ) { Text(stringResource(R.string.settings_refresh_all_keys)) }
                        OutlinedButton(
                            onClick = onOpenQrKeys,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 4.dp),
                        ) { Text(stringResource(R.string.settings_qr_import_export)) }
                        OutlinedButton(
                            onClick = onOpenSmartCard,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 4.dp),
                        ) { Text(stringResource(R.string.settings_smart_card_stub)) }
                    }
                }

                SectionHeader(stringResource(R.string.settings_openpgp_api_access))
                ElevatedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                ) {
                    Column(Modifier.padding(16.dp)) {
                        if (state.apiApps.isEmpty()) {
                            Text(
                                stringResource(R.string.settings_no_api_apps),
                                style = MaterialTheme.typography.bodySmall,
                            )
                        } else {
                            state.apiApps.forEach { app ->
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(vertical = 4.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Text(app.packageName, style = MaterialTheme.typography.bodyMedium)
                                        Text(
                                            stringResource(R.string.settings_granted_fmt, java.text.DateFormat.getDateTimeInstance().format(app.grantedAt)),
                                            style = MaterialTheme.typography.labelSmall,
                                        )
                                    }
                                    OutlinedButton(onClick = { viewModel.revokeApiApp(app.packageName) }) {
                                        Text(stringResource(R.string.common_revoke))
                                    }
                                }
                            }
                        }
                    }
                }

                SectionHeader(stringResource(R.string.settings_overlay))
                ElevatedCard(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 8.dp),
                ) {
                    Column(Modifier.padding(vertical = 4.dp)) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 16.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(Modifier.weight(1f)) {
                                Text(stringResource(R.string.settings_accessibility_service))
                                Text(
                                    if (state.accessibilityEnabled) stringResource(R.string.common_enabled) else stringResource(R.string.common_not_enabled),
                                    color = if (state.accessibilityEnabled) {
                                        MaterialTheme.colorScheme.primary
                                    } else {
                                        MaterialTheme.colorScheme.error
                                    },
                                    style = MaterialTheme.typography.bodySmall,
                                )
                            }
                            OutlinedButton(onClick = {
                                context.startActivity(Intent(Settings.ACTION_ACCESSIBILITY_SETTINGS))
                            }) { Text(stringResource(R.string.common_open)) }
                        }
                        SettingSwitchRow(
                            label = stringResource(R.string.settings_overlay_globally_enabled),
                            checked = state.settings.overlayGloballyEnabled,
                            onChecked = viewModel::setOverlayGlobal,
                        )
                        SettingSwitchRow(
                            label = stringResource(R.string.settings_show_overlay_buttons),
                            checked = state.settings.showOverlayButtons,
                            onChecked = viewModel::setShowOverlayButtons,
                        )
                        Text(
                            stringResource(R.string.onboarding_accessibility_desc),
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                        )
                        if (showOverlayConfig) {
                            OverlayConfigSection(
                                viewModel = overlayViewModel,
                                modifier = Modifier
                                    .padding(horizontal = 16.dp)
                                    .padding(top = 8.dp),
                            )
                        }
                    }
                }

                state.status?.let {
                    Text(it, modifier = Modifier.padding(top = 12.dp), style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}
