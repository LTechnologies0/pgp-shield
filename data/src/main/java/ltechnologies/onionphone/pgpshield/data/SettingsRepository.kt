package ltechnologies.onionphone.pgpshield.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Snapshot of user-configurable application settings persisted in SharedPreferences.
 *
 * @property defaultEncryptKeyId Master key id used for encryption when none is explicitly chosen.
 * @property defaultSignKeyId Master key id used for signing when none is explicitly chosen.
 * @property keyserverLookupEnabled Whether remote keyserver lookup is enabled.
 * @property keyserverUrl Base URL for OpenPGP keyserver (VKS/HKP).
 * @property showFingerprintOnList Whether key fingerprints appear in the key list UI.
 * @property backupReminderEnabled Whether to remind the user to back up keys.
 * @property overlayGloballyEnabled Master switch for the messaging overlay feature.
 * @property showOverlayButtons Whether overlay action buttons are visible.
 * @property allowScreenshots Whether the app permits screen capture (FLAG_SECURE off).
 * @property autocryptEnabled Whether Autocrypt header processing is active.
 * @property appLanguage UI language code: `system`, `en`, `fr`, `es`, `de`, `it`, or `pt`.
 */
data class AppSettings(
    val defaultEncryptKeyId: Long? = null,
    val defaultSignKeyId: Long? = null,
    val keyserverLookupEnabled: Boolean = true,
    val keyserverUrl: String = KeyserverClient.DEFAULT_URL,
    val showFingerprintOnList: Boolean = true,
    val backupReminderEnabled: Boolean = true,
    val overlayGloballyEnabled: Boolean = true,
    val showOverlayButtons: Boolean = true,
    val allowScreenshots: Boolean = false,
    val autocryptEnabled: Boolean = false,
    /** "system", "en", "fr", "es", "de", "it", "pt" */
    val appLanguage: String = "system",
)

/**
 * Reactive repository for application settings backed by SharedPreferences.
 *
 * Exposes a [StateFlow] of [AppSettings] and applies atomic read-modify-write updates.
 * Also tracks the timestamp of the last key export for backup reminders.
 */
@Singleton
class SettingsRepository @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val _settings = MutableStateFlow(read())
    val settings: StateFlow<AppSettings> = _settings.asStateFlow()

    /** Returns the current settings snapshot without subscribing to updates. */
    fun current(): AppSettings = _settings.value

    /**
     * Atomically updates settings: applies [transform], persists to disk, and emits the new value.
     */
    fun update(transform: (AppSettings) -> AppSettings) {
        val next = transform(_settings.value)
        prefs.edit()
            .putLong(KEY_DEFAULT_ENCRYPT, next.defaultEncryptKeyId ?: -1L)
            .putLong(KEY_DEFAULT_SIGN, next.defaultSignKeyId ?: -1L)
            .putBoolean(KEY_KEYSERVER, next.keyserverLookupEnabled)
            .putString(KEY_KEYSERVER_URL, next.keyserverUrl)
            .putBoolean(KEY_SHOW_FP, next.showFingerprintOnList)
            .putBoolean(KEY_BACKUP_REMINDER, next.backupReminderEnabled)
            .putBoolean(KEY_OVERLAY_GLOBAL, next.overlayGloballyEnabled)
            .putBoolean(KEY_OVERLAY_BUTTONS, next.showOverlayButtons)
            .putBoolean(KEY_ALLOW_SCREENSHOTS, next.allowScreenshots)
            .putBoolean(KEY_AUTOCRYPT, next.autocryptEnabled)
            .putString(KEY_APP_LANGUAGE, next.appLanguage)
            .apply()
        _settings.value = next
    }

    private fun read(): AppSettings {
        val enc = prefs.getLong(KEY_DEFAULT_ENCRYPT, -1L).takeIf { it >= 0 }
        val sign = prefs.getLong(KEY_DEFAULT_SIGN, -1L).takeIf { it >= 0 }
        return AppSettings(
            defaultEncryptKeyId = enc,
            defaultSignKeyId = sign,
            keyserverLookupEnabled = prefs.getBoolean(KEY_KEYSERVER, true),
            keyserverUrl = prefs.getString(KEY_KEYSERVER_URL, KeyserverClient.DEFAULT_URL)
                ?: KeyserverClient.DEFAULT_URL,
            showFingerprintOnList = prefs.getBoolean(KEY_SHOW_FP, true),
            backupReminderEnabled = prefs.getBoolean(KEY_BACKUP_REMINDER, true),
            overlayGloballyEnabled = prefs.getBoolean(KEY_OVERLAY_GLOBAL, true),
            showOverlayButtons = prefs.getBoolean(KEY_OVERLAY_BUTTONS, true),
            allowScreenshots = prefs.getBoolean(KEY_ALLOW_SCREENSHOTS, false),
            autocryptEnabled = prefs.getBoolean(KEY_AUTOCRYPT, false),
            appLanguage = prefs.getString(KEY_APP_LANGUAGE, "system") ?: "system",
        )
    }

    /** Records the current time as the last successful key export. */
    fun markKeyExported() {
        prefs.edit().putLong(KEY_LAST_EXPORT, System.currentTimeMillis()).apply()
    }

    /** @return Epoch milliseconds of the last key export, or `0` if never exported. */
    fun lastExportMillis(): Long = prefs.getLong(KEY_LAST_EXPORT, 0L)

    companion object {
        private const val PREFS_NAME = "pgp_shield_settings"
        private const val KEY_DEFAULT_ENCRYPT = "default_encrypt_key"
        private const val KEY_DEFAULT_SIGN = "default_sign_key"
        private const val KEY_CACHE_TTL = "passphrase_cache_ttl"
        private const val KEY_WIPE_SCREEN_OFF = "wipe_cache_screen_off"
        private const val KEY_KEYSERVER = "keyserver_lookup"
        private const val KEY_KEYSERVER_URL = "keyserver_url"
        private const val KEY_SHOW_FP = "show_fingerprint_list"
        private const val KEY_BACKUP_REMINDER = "backup_reminder"
        private const val KEY_OVERLAY_GLOBAL = "overlay_global"
        private const val KEY_OVERLAY_BUTTONS = "overlay_buttons"
        private const val KEY_ALLOW_SCREENSHOTS = "allow_screenshots"
        private const val KEY_AUTOCRYPT = "autocrypt_enabled"
        private const val KEY_APP_LANGUAGE = "app_language"
        private const val KEY_LAST_EXPORT = "last_key_export"
    }
}

/**
 * Size guard for armored key ring imports to prevent excessive memory use.
 */
object ImportGuard {
    /** Maximum permitted armored import size in bytes (2 MiB). */
    const val MAX_ARMORED_BYTES: Int = 2 * 1024 * 1024

    /**
     * Validates that [armored] does not exceed [MAX_ARMORED_BYTES].
     *
     * @throws IllegalArgumentException if the payload is too large.
     */
    fun checkSize(armored: ByteArray) {
        require(armored.size <= MAX_ARMORED_BYTES) {
            "Import too large (max ${MAX_ARMORED_BYTES / 1024} KB)"
        }
    }
}
