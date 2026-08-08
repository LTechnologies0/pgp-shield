package ltechnologies.onionphone.pgpshield.ui

/**
 * The app's single main Activity hosting the Compose UI.
 *
 * Must be a [FragmentActivity]: [androidx.biometric.BiometricPrompt] requires it.
 */

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.core.view.WindowCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import androidx.appcompat.app.AppCompatDelegate
import androidx.core.os.LocaleListCompat
import dagger.hilt.android.AndroidEntryPoint
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.ui.applock.AppLockGate
import ltechnologies.onionphone.pgpshield.ui.components.LocalSnackbarHostState
import ltechnologies.onionphone.pgpshield.ui.navigation.PgpShieldNavHost
import ltechnologies.onionphone.pgpshield.ui.theme.PgpShieldTheme
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper
import ltechnologies.onionphone.pgpshield.security.AppLockAuthenticator
import ltechnologies.onionphone.pgpshield.security.AppLockManager
import ltechnologies.onionphone.pgpshield.security.FidoAppLockManager
import javax.inject.Inject
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

@AndroidEntryPoint
class MainActivity : FragmentActivity() {
    @Inject lateinit var settingsRepository: SettingsRepository
    @Inject lateinit var appLockManager: AppLockManager
    @Inject lateinit var appLockAuthenticator: AppLockAuthenticator
    @Inject lateinit var fidoAppLockManager: FidoAppLockManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        applyLanguage(settingsRepository.current().appLanguage)
        WindowSecureHelper.bind(this, settingsRepository)
        lifecycleScope.launch {
            settingsRepository.settings
                .map { it.appLanguage }
                .distinctUntilChanged()
                .collect { applyLanguage(it) }
        }
        enableEdgeToEdge()
        WindowCompat.setDecorFitsSystemWindows(window, false)
        setContent {
            PgpShieldTheme {
                val snackbarHostState = remember { SnackbarHostState() }
                CompositionLocalProvider(LocalSnackbarHostState provides snackbarHostState) {
                    AppLockGate(
                        appLockManager = appLockManager,
                        authenticator = appLockAuthenticator,
                        fidoAppLockManager = fidoAppLockManager,
                    ) {
                        PgpShieldNavHost()
                    }
                }
            }
        }
    }

    private fun applyLanguage(language: String) {
        val locales = if (language == "system") {
            LocaleListCompat.getEmptyLocaleList()
        } else {
            LocaleListCompat.forLanguageTags(language)
        }
        AppCompatDelegate.setApplicationLocales(locales)
    }
}
