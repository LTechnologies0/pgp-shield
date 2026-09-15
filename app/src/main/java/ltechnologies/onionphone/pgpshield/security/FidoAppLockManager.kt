package ltechnologies.onionphone.pgpshield.security

/**
 * FIDO2 / security-key preference store for app unlock (YubiKey NFC/USB).
 *
 * Preference bits only — not a WebAuthn/CTAP authenticator. Stored in
 * EncryptedSharedPreferences (StrongBox-preferred MasterKey).
 */

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import ltechnologies.onionphone.pgpshield.data.SecurePrefs
import timber.log.Timber

data class FidoAppLockState(
    val enabled: Boolean = false,
    val credentialLabel: String? = null,
)

@Singleton
class FidoAppLockManager @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val prefs: SharedPreferences by lazy { openSecurePrefs() }

    private val _state = MutableStateFlow(FidoAppLockState())
    val state: StateFlow<FidoAppLockState> = _state.asStateFlow()

    init {
        _state.value = read()
    }

    private fun openSecurePrefs(): SharedPreferences {
        val (secure, _) = SecurePrefs.createOrReset(context, PREFS_NAME_SECURE)
        migratePlaintextIfNeeded(secure)
        return secure
    }

    private fun migratePlaintextIfNeeded(secure: SharedPreferences) {
        val legacy = context.getSharedPreferences(PREFS_NAME_LEGACY, Context.MODE_PRIVATE)
        val all = legacy.all
        if (all.isEmpty()) return
        val editor = secure.edit()
        for ((key, value) in all) {
            when (value) {
                is Boolean -> editor.putBoolean(key, value)
                is String -> editor.putString(key, value)
                is Long -> editor.putLong(key, value)
                is Int -> editor.putInt(key, value)
            }
        }
        editor.apply()
        legacy.edit().clear().apply()
        Timber.i("Migrated FIDO prefs into EncryptedSharedPreferences")
    }

    fun current(): FidoAppLockState = _state.value

    /** Registers that a FIDO/security key is required after device unlock. */
    fun registerSecurityKey(label: String = "YubiKey / FIDO2") {
        prefs.edit()
            .putBoolean(KEY_ENABLED, true)
            .putString(KEY_LABEL, label)
            .putLong(KEY_REGISTERED_AT, System.currentTimeMillis())
            .apply()
        _state.value = read()
    }

    fun clear() {
        prefs.edit().clear().apply()
        _state.value = FidoAppLockState()
    }

    fun setEnabled(enabled: Boolean) {
        if (!enabled) {
            clear()
            return
        }
        registerSecurityKey(_state.value.credentialLabel ?: "YubiKey / FIDO2")
    }

    /** True when unlock must also confirm FIDO preference (UI shows extra step). */
    fun requiresSecurityKey(): Boolean = _state.value.enabled

    private fun read(): FidoAppLockState =
        FidoAppLockState(
            enabled = prefs.getBoolean(KEY_ENABLED, false),
            credentialLabel = prefs.getString(KEY_LABEL, null),
        )

    private companion object {
        const val PREFS_NAME_LEGACY = "pgp_shield_fido"
        const val PREFS_NAME_SECURE = "pgp_shield_fido_enc"
        const val KEY_ENABLED = "fido_enabled"
        const val KEY_LABEL = "fido_label"
        const val KEY_REGISTERED_AT = "fido_registered_at"
    }
}
