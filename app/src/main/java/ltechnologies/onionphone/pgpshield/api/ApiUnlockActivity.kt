package ltechnologies.onionphone.pgpshield.api

/**
 * OpenPGP API unlock screen returned via USER_INTERACTION_REQUIRED when the vault is locked.
 *
 * Clients launch the PendingIntent, then re-execute the API call after unlock.
 */

import android.app.Activity
import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.LaunchedEffect
import androidx.fragment.app.FragmentActivity
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.security.AppLockAuthenticator
import ltechnologies.onionphone.pgpshield.security.AppLockManager
import ltechnologies.onionphone.pgpshield.security.FidoAppLockManager
import ltechnologies.onionphone.pgpshield.ui.applock.AppLockGate
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper

@AndroidEntryPoint
class ApiUnlockActivity : FragmentActivity() {
    @Inject lateinit var appLockManager: AppLockManager
    @Inject lateinit var appLockAuthenticator: AppLockAuthenticator
    @Inject lateinit var fidoAppLockManager: FidoAppLockManager
    @Inject lateinit var settingsRepository: SettingsRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        enableEdgeToEdge()
        setContent {
            PgpShieldTheme {
                AppLockGate(
                    appLockManager = appLockManager,
                    authenticator = appLockAuthenticator,
                    fidoAppLockManager = fidoAppLockManager,
                    unlockedContent = {
                        LaunchedEffect(Unit) {
                            setResult(Activity.RESULT_OK)
                            finish()
                        }
                    },
                )
            }
        }
    }

    companion object {
        const val EXTRA_CALLER_PACKAGE = "caller_package"
    }
}
