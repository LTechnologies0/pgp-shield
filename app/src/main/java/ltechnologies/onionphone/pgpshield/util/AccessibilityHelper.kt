package ltechnologies.onionphone.pgpshield.util

/**
 * Helpers for inspecting the state of the app's accessibility service.
 */

import android.content.Context
import android.provider.Settings
import android.text.TextUtils

/** Utility for querying whether an accessibility service is currently enabled. */
object AccessibilityHelper {
    /**
     * Returns `true` when [serviceClass] belonging to this app is present in the
     * system's list of enabled accessibility services.
     *
     * @param context Context used to resolve the package name and content resolver.
     * @param serviceClass The accessibility service implementation to check for.
     */
    fun isServiceEnabled(context: Context, serviceClass: Class<*>): Boolean {
        val enabled = Settings.Secure.getString(
            context.contentResolver,
            Settings.Secure.ENABLED_ACCESSIBILITY_SERVICES,
        ) ?: return false
        val expected = "${context.packageName}/${serviceClass.name}"
        return TextUtils.SimpleStringSplitter(':').let { splitter ->
            splitter.setString(enabled)
            splitter.any { it.equals(expected, ignoreCase = true) }
        }
    }
}
