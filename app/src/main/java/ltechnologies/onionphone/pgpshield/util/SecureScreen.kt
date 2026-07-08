package ltechnologies.onionphone.pgpshield.util

/**
 * Compose helper for sensitive screens.
 *
 * [MainActivity] applies [android.view.WindowManager.LayoutParams.FLAG_SECURE]
 * globally; this composable is a semantic marker for screens that handle
 * passphrases or key material.
 */

import androidx.compose.runtime.Composable

/**
 * Wraps [content] in a sensitive-screen scope (screenshot prevention is global).
 */
@Composable
fun SecureScreen(content: @Composable () -> Unit) {
    content()
}
