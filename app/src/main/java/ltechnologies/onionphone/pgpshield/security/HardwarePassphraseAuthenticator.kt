package ltechnologies.onionphone.pgpshield.security

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.crypto.Cipher
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * BiometricPrompt + CryptoObject helper for auth-bound Keystore ciphers
 * (hardware-managed OpenPGP passphrases).
 */
@Singleton
class HardwarePassphraseAuthenticator @Inject constructor() {

    /**
     * Authenticates [cipher] with BIOMETRIC_STRONG | DEVICE_CREDENTIAL and returns
     * the unlocked cipher from the CryptoObject result.
     */
    suspend fun authenticateCipher(
        activity: FragmentActivity,
        cipher: Cipher,
        title: String,
        subtitle: String,
    ): Cipher = suspendCancellableCoroutine { cont ->
        val authenticators =
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        when (BiometricManager.from(activity).canAuthenticate(authenticators)) {
            BiometricManager.BIOMETRIC_SUCCESS -> Unit
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED,
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE,
            -> {
                cont.resumeWithException(
                    IllegalStateException("Configurez un verrouillage d'écran Android d'abord"),
                )
                return@suspendCancellableCoroutine
            }
            else -> Unit
        }

        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val unlocked = result.cryptoObject?.cipher
                    if (unlocked == null) {
                        cont.resumeWithException(
                            IllegalStateException("BiometricPrompt n'a pas renvoyé de Cipher"),
                        )
                    } else if (cont.isActive) {
                        cont.resume(unlocked)
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (!cont.isActive) return
                    if (errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                    ) {
                        cont.resumeWithException(AuthCancelledException(errString.toString()))
                    } else {
                        cont.resumeWithException(IllegalStateException(errString.toString()))
                    }
                }

                override fun onAuthenticationFailed() = Unit
            },
        )

        cont.invokeOnCancellation {
            runCatching { prompt.cancelAuthentication() }
        }

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(authenticators)
            .build()

        prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
    }
}

/** User dismissed the PIN/biometric prompt. */
class AuthCancelledException(message: String) : Exception(message)
