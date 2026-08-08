package ltechnologies.onionphone.pgpshield.security

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import javax.inject.Inject
import javax.inject.Singleton

sealed class AppLockAuthResult {
    data object Success : AppLockAuthResult()
    data class Failure(val message: String) : AppLockAuthResult()
    data object Cancelled : AppLockAuthResult()
}

/**
 * System lock prompt: BIOMETRIC_STRONG | DEVICE_CREDENTIAL.
 * Works in private profiles when a screen lock exists (OnionVPN / SecureMessenger pattern).
 */
@Singleton
class AppLockAuthenticator @Inject constructor() {

    fun authenticate(
        activity: FragmentActivity,
        onResult: (AppLockAuthResult) -> Unit,
    ) {
        val manager = BiometricManager.from(activity)
        val authenticators =
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        when (manager.canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Unit
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED,
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            -> {
                onResult(AppLockAuthResult.Failure("Configurez un verrouillage d'écran Android d'abord"))
                return
            }
            else -> Unit
        }

        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onResult(AppLockAuthResult.Success)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                    ) {
                        onResult(AppLockAuthResult.Cancelled)
                    } else {
                        onResult(AppLockAuthResult.Failure(errString.toString()))
                    }
                }

                override fun onAuthenticationFailed() = Unit
            },
        )

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Déverrouiller PGP Shield")
            .setSubtitle("Empreinte, visage ou code PIN de l'appareil")
            .setAllowedAuthenticators(authenticators)
            .build()

        prompt.authenticate(info)
    }

    /**
     * Second-factor prompt for FIDO / security-key preference: BIOMETRIC_STRONG only
     * (no device PIN fallback), so a Class-3 biometric or integrated security key is required.
     */
    fun confirmSecurityKey(
        activity: FragmentActivity,
        label: String?,
        onResult: (AppLockAuthResult) -> Unit,
    ) {
        val manager = BiometricManager.from(activity)
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG
        when (manager.canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Unit
            else -> {
                // Fall back to device credential when no Class-3 biometric is enrolled —
                // still forces an interactive second factor after the preference is enabled.
                authenticate(activity, onResult)
                return
            }
        }
        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onResult(AppLockAuthResult.Success)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                    ) {
                        onResult(AppLockAuthResult.Cancelled)
                    } else {
                        onResult(AppLockAuthResult.Failure(errString.toString()))
                    }
                }

                override fun onAuthenticationFailed() = Unit
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Clé de sécurité / FIDO")
            .setSubtitle(label ?: "Confirmez avec biométrie forte ou clé de sécurité")
            .setNegativeButtonText("Annuler")
            .setAllowedAuthenticators(authenticators)
            .build()
        prompt.authenticate(info)
    }
}
