package ltechnologies.onionphone.pgpshield.util

/**
 * Clipboard utility that flags copied content as sensitive and auto-clears it.
 */

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import timber.log.Timber

/** Copies secret text to the system clipboard and schedules its removal. */
object SensitiveClipboard {
    private val handler = Handler(Looper.getMainLooper())
    private const val DEFAULT_CLEAR_MS = 60_000L

    /**
     * Copies [text] to the clipboard, marking it sensitive on Android 13+, then
     * schedules an automatic clear.
     *
     * @param label Clipboard label shown to the system.
     * @param text The secret content to place on the clipboard.
     * @param clearAfterMs Delay before the clipboard is cleared if unchanged.
     */
    fun copy(
        context: Context,
        label: String,
        text: String,
        clearAfterMs: Long = DEFAULT_CLEAR_MS,
    ) {
        val cm = context.getSystemService(ClipboardManager::class.java)
        if (cm == null) {
            Timber.e("Clipboard unavailable")
            return
        }
        val clip = ClipData.newPlainText(label, text)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        }
        cm.setPrimaryClip(clip)
        scheduleClear(cm, context, text, clearAfterMs)
    }

    private fun scheduleClear(cm: ClipboardManager, context: Context, expected: String, delayMs: Long) {
        handler.postDelayed({
            runCatching {
                val current = cm.primaryClip?.getItemAt(0)?.coerceToText(context)?.toString()
                if (current == expected) {
                    cm.clearPrimaryClip()
                }
            }.onFailure { e ->
                Timber.d(e, "Clipboard auto-clear skipped")
            }
        }, delayMs)
    }
}
