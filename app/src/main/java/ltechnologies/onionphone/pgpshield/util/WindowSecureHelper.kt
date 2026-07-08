package ltechnologies.onionphone.pgpshield.util

/**
 * Applies and observes the `FLAG_SECURE` screenshot/recording policy on windows.
 */

import android.app.Activity
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.lifecycleScope
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch

/** Controls whether an activity's window permits screenshots and screen capture. */
object WindowSecureHelper {
    /**
     * Enables or disables `FLAG_SECURE` on [activity] according to
     * [allowScreenshots] and records the applied policy for diagnostics.
     */
    fun apply(activity: Activity, allowScreenshots: Boolean) {
        if (allowScreenshots) disable(activity) else enable(activity)
        // #region agent log
        DebugAgentLog.log(
            location = "WindowSecureHelper.kt:apply",
            message = "screenshot policy applied",
            data = mapOf("allowScreenshots" to allowScreenshots),
            hypothesisId = "screenshot",
        )
        // #endregion
    }

    /** Applies screenshot policy now, on resume, and whenever the setting changes. */
    fun bind(activity: ComponentActivity, settingsRepository: SettingsRepository) {
        val applyNow = { apply(activity, settingsRepository.current().allowScreenshots) }
        applyNow()
        activity.lifecycle.addObserver(object : DefaultLifecycleObserver {
            override fun onResume(owner: LifecycleOwner) = applyNow()
        })
        activity.lifecycleScope.launch {
            settingsRepository.settings
                .map { it.allowScreenshots }
                .distinctUntilChanged()
                .collect { apply(activity, it) }
        }
    }

    /** Sets `FLAG_SECURE` to block screenshots and screen recording. */
    fun enable(activity: Activity) {
        activity.window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE,
        )
    }

    /** Clears `FLAG_SECURE`, allowing screenshots and screen recording. */
    fun disable(activity: Activity) {
        activity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
    }
}
