package ltechnologies.onionphone.pgpshield.overlay

/**
 * Resolves a UI [android.content.Context] + [android.view.WindowManager] pair for
 * accessibility overlays.
 *
 * The ACS itself is a non-visual Context on recent Android: creating Views or
 * fetching [android.view.WindowManager] from it throws. A window context typed
 * [android.view.WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY] is the
 * supported host for overlay chrome and decrypt bubbles.
 *
 * Hosts are cached per attached ACS so addView/removeView share the same
 * WindowManager identity (otherwise removeView fails and overlays leak).
 */

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.hardware.display.DisplayManager
import android.os.Build
import android.view.Display
import android.view.WindowManager
import timber.log.Timber

internal data class OverlayWindowHost(
    val context: Context,
    val windowManager: WindowManager,
)

private var cachedService: AccessibilityService? = null
private var cachedHost: OverlayWindowHost? = null

internal fun AccessibilityService.clearOverlayWindowHost() {
    if (cachedService === this) {
        cachedService = null
        cachedHost = null
    }
}

internal fun AccessibilityService.overlayWindowHost(): OverlayWindowHost? {
    if (cachedService === this) {
        cachedHost?.let { return it }
    }

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
        runCatching {
            val windowContext = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val dm = getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
                val display = dm.getDisplay(Display.DEFAULT_DISPLAY)
                    ?: return@runCatching null
                createWindowContext(
                    display,
                    WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
                    null,
                )
            } else {
                @Suppress("DEPRECATION")
                createWindowContext(WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY, null)
            }
            @Suppress("DEPRECATION")
            val wm = windowContext.getSystemService(Context.WINDOW_SERVICE) as? WindowManager
                ?: return@runCatching null
            OverlayWindowHost(windowContext, wm)
        }.onFailure { Timber.w(it, "overlay window host failed") }
            .getOrNull()
            ?.let { host ->
                cachedService = this
                cachedHost = host
                return host
            }
    }

    runCatching {
        @Suppress("DEPRECATION")
        val wm = getSystemService(Context.WINDOW_SERVICE) as? WindowManager ?: return@runCatching null
        OverlayWindowHost(this, wm)
    }.getOrNull()?.let { host ->
        cachedService = this
        cachedHost = host
        return host
    }

    Timber.w("Overlay window host unavailable")
    return null
}

internal fun AccessibilityService.overlayWindowManager(): WindowManager? =
    overlayWindowHost()?.windowManager
