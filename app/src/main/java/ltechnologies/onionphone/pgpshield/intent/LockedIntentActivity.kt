package ltechnologies.onionphone.pgpshield.intent

import androidx.activity.compose.setContent
import androidx.compose.runtime.Composable
import androidx.fragment.app.FragmentActivity
import javax.inject.Inject
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.security.AppLockAuthenticator
import ltechnologies.onionphone.pgpshield.security.AppLockManager
import ltechnologies.onionphone.pgpshield.security.FidoAppLockManager
import ltechnologies.onionphone.pgpshield.ui.applock.AppLockGate
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper

/**
 * Intent activities that must unlock the vault (biometric / device credential)
 * before reading secret key material — same gate as [ltechnologies.onionphone.pgpshield.ui.MainActivity].
 */
abstract class LockedIntentActivity : FragmentActivity() {
    @Inject lateinit var appLockManager: AppLockManager
    @Inject lateinit var appLockAuthenticator: AppLockAuthenticator
    @Inject lateinit var fidoAppLockManager: FidoAppLockManager

    protected fun setVaultGatedContent(
        settingsRepository: SettingsRepository,
        content: @Composable () -> Unit,
    ) {
        WindowSecureHelper.bind(this, settingsRepository)
        setContent {
            PgpShieldTheme {
                AppLockGate(
                    appLockManager = appLockManager,
                    authenticator = appLockAuthenticator,
                    fidoAppLockManager = fidoAppLockManager,
                    unlockedContent = content,
                )
            }
        }
    }
}
