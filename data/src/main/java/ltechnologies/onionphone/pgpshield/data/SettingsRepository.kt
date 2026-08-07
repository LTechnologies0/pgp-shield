package ltechnologies.onionphone.pgpshield.data

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Snapshot of user-configurable application settings persisted in encrypted SharedPreferences.
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
 * Reactive repository for application settings backed by StrongBox/TEE-encrypted prefs.
 *
 * Migrates once from the legacy cleartext `pgp_shield_settings` file.
 */
@Singleton
class SettingsRepository @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val appContext = context.applicationContext
    private val prefs: SharedPreferences = openPrefs(appContext)
    private val _settings = MutableStateFlow(read())
    val settings: StateFlow<AppSettings> = _settings.asStateFlow()

    fun current(): AppSettings = _settings.value

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

    fun markKeyExported() {
        prefs.edit().putLong(KEY_LAST_EXPORT, System.currentTimeMillis()).apply()
    }

    fun lastExportMillis(): Long = prefs.getLong(KEY_LAST_EXPORT, 0L)

    companion object {
        private const val PREFS_NAME = "pgp_shield_settings_enc"
        private const val LEGACY_PREFS_NAME = "pgp_shield_settings"
        private const val KEY_DEFAULT_ENCRYPT = "default_encrypt_key"
        private const val KEY_DEFAULT_SIGN = "default_sign_key"
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
        private const val KEY_MIGRATED = "migrated_from_cleartext_v1"

        private fun openPrefs(context: Context): SharedPreferences {
            val enc = SecurePrefs.create(context, PREFS_NAME)
            if (!enc.getBoolean(KEY_MIGRATED, false)) {
                migrateFromCleartext(context, enc)
            }
            return enc
        }

        private fun migrateFromCleartext(context: Context, enc: SharedPreferences) {
            val legacy = context.getSharedPreferences(LEGACY_PREFS_NAME, Context.MODE_PRIVATE)
            val editor = enc.edit()
            for ((key, value) in legacy.all) {
                when (value) {
                    is Boolean -> editor.putBoolean(key, value)
                    is Int -> editor.putInt(key, value)
                    is Long -> editor.putLong(key, value)
                    is Float -> editor.putFloat(key, value)
                    is String -> editor.putString(key, value)
                    is Set<*> -> @Suppress("UNCHECKED_CAST")
                    editor.putStringSet(key, value as Set<String>)
                }
            }
            editor.putBoolean(KEY_MIGRATED, true).apply()
            legacy.edit().clear().apply()
        }
    }
}

/** Size guard for armored key ring imports to prevent excessive memory use. */
object ImportGuard {
    const val MAX_ARMORED_BYTES: Int = 2 * 1024 * 1024

    fun checkSize(armored: ByteArray) {
        require(armored.size <= MAX_ARMORED_BYTES) {
            "Import too large (max ${MAX_ARMORED_BYTES / 1024} KB)"
        }
    }
}
