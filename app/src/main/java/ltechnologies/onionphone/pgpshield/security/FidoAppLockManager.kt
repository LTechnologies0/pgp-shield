package ltechnologies.onionphone.pgpshield.security

/**
 * FIDO2 / security-key preference store for app unlock (YubiKey NFC/USB).
 */

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class FidoAppLockState(
    val enabled: Boolean = false,
    val credentialLabel: String? = null,
)

@Singleton
class FidoAppLockManager @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("pgp_shield_fido", Context.MODE_PRIVATE)

    private val _state = MutableStateFlow(read())
    val state: StateFlow<FidoAppLockState> = _state.asStateFlow()

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
        const val KEY_ENABLED = "fido_enabled"
        const val KEY_LABEL = "fido_label"
        const val KEY_REGISTERED_AT = "fido_registered_at"
    }
}
