package ltechnologies.onionphone.pgpshield.ui.settings

/**
 * State holder for the settings screen: app preferences, key defaults, keyserver
 * options and granted API applications.
 */

import android.content.Context
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.AppSettings
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeySummary
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.data.db.ApiAllowedKeyDao
import ltechnologies.onionphone.pgpshield.data.db.ApiAppDao
import ltechnologies.onionphone.pgpshield.data.db.ApiAppEntity
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.withContext

/** Immutable UI state for the settings screen. */
data class SettingsUiState(
    val settings: AppSettings = AppSettings(),
    val keys: List<KeySummary> = emptyList(),
    val apiApps: List<ApiAppEntity> = emptyList(),
    /** Per-package restricted key ids; empty list means all secret keys are allowed. */
    val apiAllowedKeysByApp: Map<String, List<Long>> = emptyMap(),
    val status: String? = null,
    val accessibilityEnabled: Boolean = false,
    val isBusy: Boolean = false,
)

/**
 * [ViewModel] that combines persisted settings, keys, granted API apps and
 * accessibility state into a single [SettingsUiState] and applies user changes.
 */
@HiltViewModel
class SettingsViewModel @Inject constructor(
    @ApplicationContext private val context: Context,
    private val keyRepository: KeyRepository,
    private val settingsRepository: SettingsRepository,
    private val apiAppDao: ApiAppDao,
    private val apiAllowedKeyDao: ApiAllowedKeyDao,
) : ViewModel() {
    private val _accessibilityEnabled = MutableStateFlow(false)
    private val _status = MutableStateFlow<String?>(null)
    private val _isBusy = MutableStateFlow(false)

    val uiState: StateFlow<SettingsUiState> = combine(
        combine(
            settingsRepository.settings,
            keyRepository.observeKeys(),
            apiAppDao.observeAll(),
            apiAllowedKeyDao.observeAll(),
        ) { settings, keys, apiApps, allowedRows ->
            Quadruple(settings, keys, apiApps, allowedRows)
        },
        combine(_accessibilityEnabled, _status, _isBusy) { acs, status, busy ->
            Triple(acs, status, busy)
        },
    ) { meta, flags ->
        SettingsUiState(
            settings = meta.first,
            keys = meta.second,
            apiApps = meta.third,
            apiAllowedKeysByApp = meta.fourth
                .groupBy { it.packageName }
                .mapValues { (_, rows) -> rows.map { it.keyId }.distinct().sorted() },
            accessibilityEnabled = flags.first,
            status = flags.second,
            isBusy = flags.third,
        )
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), SettingsUiState())

    private data class Quadruple<A, B, C, D>(
        val first: A,
        val second: B,
        val third: C,
        val fourth: D,
    )

    /** Updates the cached accessibility-service enabled flag. */
    fun refreshAccessibility(enabled: Boolean) {
        _accessibilityEnabled.value = enabled
    }

    /** Sets the key preselected for encryption, or clears it when null. */
    fun setDefaultEncryptKey(keyId: Long?) {
        updateSettings { it.copy(defaultEncryptKeyId = keyId) }
    }

    /** Sets the key preselected for signing, or clears it when null. */
    fun setDefaultSignKey(keyId: Long?) {
        updateSettings { it.copy(defaultSignKeyId = keyId) }
    }

    /** Enables or disables keyserver lookups. */
    fun setKeyserverLookup(enabled: Boolean) {
        updateSettings { it.copy(keyserverLookupEnabled = enabled) }
    }

    /** Sets the keyserver base URL (trimmed). */
    fun setKeyserverUrl(url: String) {
        updateSettings { it.copy(keyserverUrl = url.trim()) }
    }

    /** Toggles showing fingerprints in the key list. */
    fun setShowFingerprint(enabled: Boolean) {
        updateSettings { it.copy(showFingerprintOnList = enabled) }
    }

    /** Toggles periodic backup reminders. */
    fun setBackupReminder(enabled: Boolean) {
        updateSettings { it.copy(backupReminderEnabled = enabled) }
    }

    /** Enables or disables the encrypt/decrypt overlay globally. */
    fun setOverlayGlobal(enabled: Boolean) {
        updateSettings { it.copy(overlayGloballyEnabled = enabled) }
    }

    /** Toggles visibility of the floating overlay action buttons. */
    fun setShowOverlayButtons(enabled: Boolean) {
        updateSettings { it.copy(showOverlayButtons = enabled) }
    }

    /** Allows or blocks screenshots/screen recording of sensitive screens. */
    fun setAllowScreenshots(enabled: Boolean) {
        updateSettings { it.copy(allowScreenshots = enabled) }
    }

    /** Enables or disables Autocrypt header handling. */
    fun setAutocrypt(enabled: Boolean) {
        updateSettings { it.copy(autocryptEnabled = enabled) }
    }

    /** Sets OpenPGP interop profile (`RFC9580_MODERN` / `LIBREPGP_GNUPG` / `LEGACY_MDC`). */
    fun setInteropProfile(profile: String) {
        updateSettings { it.copy(interopProfile = profile) }
    }

    /** Sets the in-app language override. */
    fun setAppLanguage(language: String) {
        updateSettings { it.copy(appLanguage = language) }
    }

    /** Refreshes all stored keys from the configured keyserver, reporting progress via status. */
    fun refreshAllKeys() {
        viewModelScope.launch {
            _isBusy.value = true
            try {
                val settings = settingsRepository.current()
                if (!settings.keyserverLookupEnabled) {
                    _status.value = context.getString(R.string.settings_keyserver_disabled)
                    return@launch
                }
                val url = settings.keyserverUrl
                _status.value = context.getString(R.string.settings_keyserver_refreshing)
                val keys = keyRepository.observeKeys().first()
                val ok = withContext(Dispatchers.IO) {
                    coroutineScope {
                        val limit = Semaphore(3)
                        keys.map { key ->
                            async {
                                limit.acquire()
                                try {
                                    runCatching {
                                        keyRepository.refreshKeyFromKeyserver(key.masterKeyId, url)
                                        1
                                    }.getOrDefault(0)
                                } finally {
                                    limit.release()
                                }
                            }
                        }.sumOf { it.await() }
                    }
                }
                _status.value = context.getString(R.string.settings_keyserver_refreshed_fmt, ok, keys.size)
            } catch (e: Exception) {
                _status.value = e.message ?: context.getString(R.string.settings_keyserver_refresh_failed)
            } finally {
                _isBusy.value = false
            }
        }
    }

    /** Revokes all API access and allowed keys for the given caller package. */
    fun revokeApiApp(packageName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            apiAllowedKeyDao.clearForApp(packageName)
            apiAppDao.revoke(packageName)
            _status.value = context.getString(R.string.settings_api_revoked_fmt, packageName)
        }
    }

    private fun updateSettings(transform: (AppSettings) -> AppSettings) {
        viewModelScope.launch(Dispatchers.IO) {
            settingsRepository.update(transform)
        }
    }
}
