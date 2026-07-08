package ltechnologies.onionphone.pgpshield.ui.settings

/**
 * State holder for the settings screen: app preferences, key defaults, keyserver
 * options and granted API applications.
 */

import androidx.lifecycle.ViewModel

import androidx.lifecycle.viewModelScope

import dagger.hilt.android.lifecycle.HiltViewModel

import ltechnologies.onionphone.pgpshield.data.AppSettings

import ltechnologies.onionphone.pgpshield.data.KeyRepository

import ltechnologies.onionphone.pgpshield.data.KeySummary

import ltechnologies.onionphone.pgpshield.data.SettingsRepository

import ltechnologies.onionphone.pgpshield.data.db.ApiAllowedKeyDao

import ltechnologies.onionphone.pgpshield.data.db.ApiAppDao

import ltechnologies.onionphone.pgpshield.data.db.ApiAppEntity

import javax.inject.Inject

import kotlinx.coroutines.flow.MutableStateFlow

import kotlinx.coroutines.flow.SharingStarted

import kotlinx.coroutines.flow.StateFlow

import kotlinx.coroutines.flow.combine

import kotlinx.coroutines.flow.first

import kotlinx.coroutines.flow.stateIn

import kotlinx.coroutines.launch



/** Immutable UI state for the settings screen. */
data class SettingsUiState(

    val settings: AppSettings = AppSettings(),

    val keys: List<KeySummary> = emptyList(),

    val apiApps: List<ApiAppEntity> = emptyList(),

    val status: String? = null,

    val accessibilityEnabled: Boolean = false,

)



/**
 * [ViewModel] that combines persisted settings, keys, granted API apps and
 * accessibility state into a single [SettingsUiState] and applies user changes.
 */
@HiltViewModel

class SettingsViewModel @Inject constructor(

    private val keyRepository: KeyRepository,

    private val settingsRepository: SettingsRepository,

    private val apiAppDao: ApiAppDao,

    private val apiAllowedKeyDao: ApiAllowedKeyDao,

) : ViewModel() {

    private val _accessibilityEnabled = MutableStateFlow(false)

    private val _status = MutableStateFlow<String?>(null)



    val uiState: StateFlow<SettingsUiState> = combine(

        settingsRepository.settings,

        keyRepository.observeKeys(),

        apiAppDao.observeAll(),

        _accessibilityEnabled,

        _status,

    ) { settings, keys, apiApps, acs, status ->

        SettingsUiState(settings, keys, apiApps, status, acs)

    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), SettingsUiState())



    /** Updates the cached accessibility-service enabled flag. */
    fun refreshAccessibility(enabled: Boolean) {

        _accessibilityEnabled.value = enabled

    }



    /** Sets the key preselected for encryption, or clears it when null. */
    fun setDefaultEncryptKey(keyId: Long?) {

        settingsRepository.update { it.copy(defaultEncryptKeyId = keyId) }

    }



    /** Sets the key preselected for signing, or clears it when null. */
    fun setDefaultSignKey(keyId: Long?) {

        settingsRepository.update { it.copy(defaultSignKeyId = keyId) }

    }



    /** Enables or disables keyserver lookups. */
    fun setKeyserverLookup(enabled: Boolean) {

        settingsRepository.update { it.copy(keyserverLookupEnabled = enabled) }

    }



    /** Sets the keyserver base URL (trimmed). */
    fun setKeyserverUrl(url: String) {

        settingsRepository.update { it.copy(keyserverUrl = url.trim()) }

    }



    /** Toggles showing fingerprints in the key list. */
    fun setShowFingerprint(enabled: Boolean) {

        settingsRepository.update { it.copy(showFingerprintOnList = enabled) }

    }



    /** Toggles periodic backup reminders. */
    fun setBackupReminder(enabled: Boolean) {

        settingsRepository.update { it.copy(backupReminderEnabled = enabled) }

    }



    /** Enables or disables the encrypt/decrypt overlay globally. */
    fun setOverlayGlobal(enabled: Boolean) {

        settingsRepository.update { it.copy(overlayGloballyEnabled = enabled) }

    }



    /** Toggles visibility of the floating overlay action buttons. */
    fun setShowOverlayButtons(enabled: Boolean) {

        settingsRepository.update { it.copy(showOverlayButtons = enabled) }

    }



    /** Allows or blocks screenshots/screen recording of sensitive screens. */
    fun setAllowScreenshots(enabled: Boolean) {

        settingsRepository.update { it.copy(allowScreenshots = enabled) }

    }



    /** Enables or disables Autocrypt header handling. */
    fun setAutocrypt(enabled: Boolean) {

        settingsRepository.update { it.copy(autocryptEnabled = enabled) }

    }

    /** Sets the in-app language override. */
    fun setAppLanguage(language: String) {
        settingsRepository.update { it.copy(appLanguage = language) }
    }



    /** Refreshes all stored keys from the configured keyserver, reporting progress via status. */
    fun refreshAllKeys() {

        viewModelScope.launch {

            try {

                val settings = settingsRepository.current()
                if (!settings.keyserverLookupEnabled) {
                    _status.value = "Keyserver lookup is disabled in Settings"
                    return@launch
                }
                val url = settings.keyserverUrl

                val keys = keyRepository.observeKeys().first()

                var ok = 0

                for (key in keys) {

                    runCatching {

                        keyRepository.refreshKeyFromKeyserver(key.masterKeyId, url)

                        ok++

                    }

                }

                _status.value = "Refreshed $ok of ${keys.size} keys from keyserver"

            } catch (e: Exception) {

                _status.value = e.message ?: "Refresh failed"

            }

        }

    }



    /** Revokes all API access and allowed keys for the given caller package. */
    fun revokeApiApp(packageName: String) {

        viewModelScope.launch {

            apiAllowedKeyDao.clearForApp(packageName)

            apiAppDao.revoke(packageName)

            _status.value = "Revoked API access for $packageName"

        }

    }

}


