package ltechnologies.onionphone.pgpshield.overlay

/**
 * Accessibility service that feeds foreground/focus events to the overlay.
 */

import android.accessibilityservice.AccessibilityService
import android.os.SystemClock
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import timber.log.Timber

/**
 * Hilt-injected [AccessibilityService] backing the encrypt/decrypt overlay.
 *
 * It observes window and focus changes to notify [OverlayCoordinator] about the
 * foreground app, the focused editable field, and potential "send" clicks, while
 * throttling content-change rescans. It never reacts to its own package.
 */
@AndroidEntryPoint
class ShieldAccessibilityService : AccessibilityService() {
    @Inject lateinit var overlayCoordinator: OverlayCoordinator

    private var lastPackage: String? = null
    private var lastContentRefreshAt = 0L

    /** Routes accessibility events to the [OverlayCoordinator]. */
    override fun onAccessibilityEvent(event: AccessibilityEvent?) {
        if (event == null) return
        val pkg = event.packageName?.toString() ?: return
        if (pkg == packageName) return

        if (pkg != lastPackage) {
            lastPackage = pkg
            overlayCoordinator.onForegroundAppChanged(pkg)
        }

        when (event.eventType) {
            AccessibilityEvent.TYPE_VIEW_FOCUSED,
            AccessibilityEvent.TYPE_VIEW_TEXT_SELECTION_CHANGED,
            -> {
                val source = event.source
                try {
                    if (source != null && isGoodEditable(source)) {
                        overlayCoordinator.onEditableFieldFocused(
                            AccessibilityNodeInfo.obtain(source),
                        )
                    }
                } finally {
                    source?.recycle()
                }
            }
            AccessibilityEvent.TYPE_WINDOW_CONTENT_CHANGED -> {
                if (overlayCoordinator.hasFocusTarget()) return
                val now = SystemClock.uptimeMillis()
                if (now - lastContentRefreshAt < CONTENT_REFRESH_GAP_MS) return
                lastContentRefreshAt = now
                val root = rootInActiveWindow
                try {
                    overlayCoordinator.refreshFocusedFieldFromRoot(root)
                } finally {
                    root?.recycle()
                }
            }
            AccessibilityEvent.TYPE_VIEW_CLICKED -> {
                val source = event.source
                try {
                    if (source != null) {
                        overlayCoordinator.onPotentialSendAction(AccessibilityNodeInfo.obtain(source))
                    }
                } finally {
                    source?.recycle()
                }
            }
        }
    }

    /** Hides the overlay when the accessibility feedback is interrupted. */
    override fun onInterrupt() {
        overlayCoordinator.hideAll()
    }

    /** Attaches this service to the coordinator once connected. */
    override fun onServiceConnected() {
        super.onServiceConnected()
        Timber.i("ShieldAccessibilityService connected")
        overlayCoordinator.attachService(this)
    }

    /** Detaches from the coordinator when the service is destroyed. */
    override fun onDestroy() {
        overlayCoordinator.detachService()
        super.onDestroy()
    }

    private fun isGoodEditable(node: AccessibilityNodeInfo): Boolean =
        node.isEditable &&
            node.isVisibleToUser &&
            (node.isFocused || node.isAccessibilityFocused) &&
            (node.className?.contains("EditText") == true)

    companion object {
        private const val CONTENT_REFRESH_GAP_MS = 750L
    }
}
