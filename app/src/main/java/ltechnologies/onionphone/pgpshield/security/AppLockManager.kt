package ltechnologies.onionphone.pgpshield.security

import android.app.KeyguardManager
import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import ltechnologies.onionphone.pgpshield.data.security.VaultAccessPolicy

enum class AppLockState {
    DEVICE_INSECURE,
    LOCKED,
    UNLOCKED,
}

/**
 * Mandatory app lock tied to the Android device credential (PIN / pattern / biometric).
 * Secret vault access is refused while [LOCKED].
 */
@Singleton
class AppLockManager @Inject constructor(
    @ApplicationContext private val context: Context,
) : VaultAccessPolicy {
    private val keyguard = context.getSystemService(KeyguardManager::class.java)

    private val _state = MutableStateFlow(initialState())
    val state: StateFlow<AppLockState> = _state.asStateFlow()

    val isDeviceSecure: Boolean
        get() = keyguard?.isDeviceSecure == true

    val isUnlocked: Boolean
        get() = _state.value == AppLockState.UNLOCKED

    private fun initialState(): AppLockState =
        if (isDeviceSecure) AppLockState.LOCKED else AppLockState.DEVICE_INSECURE

    suspend fun awaitUnlocked() {
        state.first { it == AppLockState.UNLOCKED }
    }

    fun markUnlocked() {
        _state.value = AppLockState.UNLOCKED
    }

    fun lock() {
        if (!isDeviceSecure) {
            _state.value = AppLockState.DEVICE_INSECURE
            return
        }
        _state.value = AppLockState.LOCKED
    }

    override fun assertSecretsAccessible() {
        check(isUnlocked || _state.value == AppLockState.DEVICE_INSECURE) {
            "App is locked — authenticate with device lock first"
        }
    }
}
