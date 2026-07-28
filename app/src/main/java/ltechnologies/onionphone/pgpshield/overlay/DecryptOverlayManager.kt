package ltechnologies.onionphone.pgpshield.overlay

/**
 * Oversec-style in-place decrypt overlays: finds ciphertext TextViews in the
 * active window and draws translucent plaintext bubbles above them.
 */

import android.accessibilityservice.AccessibilityService
import android.graphics.PixelFormat
import android.graphics.Rect
import android.view.Gravity
import android.view.WindowManager
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.FrameLayout
import android.widget.TextView
import androidx.core.graphics.toColorInt
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.db.OverlayAppConfigEntity
import ltechnologies.onionphone.pgpshield.encoding.EncodingMethod
import ltechnologies.onionphone.pgpshield.encoding.EncodingRegistry
import ltechnologies.onionphone.pgpshield.encoding.ZeroWidthEncoder
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import timber.log.Timber

/**
 * Manages floating plaintext overlays that sit on top of encrypted chat bubbles
 * (Oversec's signature UX): ciphertext stays in the messenger; plaintext is shown
 * as a translucent accessibility overlay positioned over each matching node.
 */
@Singleton
class DecryptOverlayManager @Inject constructor(
    private val keyRepository: KeyRepository,
    private val cryptoOperations: CryptoOperations,
    private val passphraseSession: OverlayPassphraseSession,
) {
    private data class Bubble(
        val view: FrameLayout,
        val fingerprint: String,
    )

    private val bubbles = mutableListOf<Bubble>()
    private var service: AccessibilityService? = null

    fun attach(acs: AccessibilityService) {
        service = acs
    }

    fun detach() {
        clearBubbles()
        service = null
    }

    fun clearBubbles() {
        val acs = service ?: return
        val wm = acs.overlayWindowManager() ?: run {
            bubbles.clear()
            return
        }
        bubbles.forEach { bubble ->
            try {
                wm.removeView(bubble.view)
            } catch (_: Exception) {
            }
        }
        bubbles.clear()
    }

    /**
     * Scans [root] for ciphertext-looking nodes and refreshes decrypt bubbles
     * when [config] has a decrypt key configured.
     */
    suspend fun refreshFromRoot(root: AccessibilityNodeInfo?, config: OverlayAppConfigEntity) {
        if (root == null) return
        val candidates = findCiphertextNodes(root)
        if (candidates.isEmpty()) {
            clearBubbles()
            return
        }
        val decrypted = mutableListOf<Pair<Rect, String>>()
        for ((bounds, text) in candidates) {
            val plain = decodeCandidate(text, config) ?: continue
            if (plain.isBlank() || plain == text) continue
            decrypted += bounds to plain
        }
        renderBubbles(decrypted)
    }

    private suspend fun decodeCandidate(text: String, config: OverlayAppConfigEntity): String? {
        val method = EncodingRegistry.parseId(config.encodingMethod)
        // Oversec path: decoy + zero-width payload (may itself be armored PGP)
        if (ZeroWidthEncoder.containsPayload(text)) {
            val hidden = ZeroWidthEncoder.decode(text)
            if (!hidden.isNullOrBlank()) {
                if (hidden.contains("BEGIN PGP")) {
                    return gpgDecode(hidden, config)
                }
                return hidden
            }
        }
        return when {
            text.contains("BEGIN PGP MESSAGE") || text.contains("BEGIN PGP SIGNED") ->
                gpgDecode(text, config)
            method == EncodingMethod.BASE64 && text.matches(Regex("^[A-Za-z0-9+/=\\r\\n]{16,}$")) ->
                runCatching {
                    ltechnologies.onionphone.pgpshield.encoding.Base64Encoder.decode(text)
                }.getOrNull()
            else -> null
        }
    }

    private suspend fun gpgDecode(text: String, config: OverlayAppConfigEntity): String? {
        val keyId = config.decryptKeyId ?: return null
        val secret = withContext(Dispatchers.IO) { keyRepository.getArmoredSecret(keyId) } ?: return null
        val passphrase = passphraseSession.get(keyId)
        if (passphrase == null) {
            Timber.d("Decrypt overlay: passphrase needed for key %s", keyId.toString(16))
            return null
        }
        return try {
            val result = cryptoOperations.decrypt(text.toByteArray(Charsets.UTF_8), secret, passphrase)
            String(result.plaintext, Charsets.UTF_8)
        } catch (e: Exception) {
            Timber.d(e, "Decrypt overlay GPG failed")
            null
        } finally {
            passphrase.fill('\u0000')
        }
    }

    private fun findCiphertextNodes(root: AccessibilityNodeInfo): List<Pair<Rect, String>> {
        val out = mutableListOf<Pair<Rect, String>>()
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(AccessibilityNodeInfo.obtain(root))
        while (queue.isNotEmpty()) {
            val node = queue.removeFirst()
            try {
                val text = node.text?.toString().orEmpty()
                if (text.isNotBlank() && looksLikeCiphertext(text) && node.isVisibleToUser) {
                    val bounds = Rect()
                    node.getBoundsInScreen(bounds)
                    if (bounds.width() > 40 && bounds.height() > 20) {
                        out += bounds to text
                    }
                }
                for (i in 0 until node.childCount) {
                    node.getChild(i)?.let { queue.add(it) }
                }
            } finally {
                node.recycle()
            }
        }
        return out.take(MAX_BUBBLES)
    }

    private fun looksLikeCiphertext(text: String): Boolean {
        val trimmed = text.trim()
        return trimmed.contains("BEGIN PGP MESSAGE") ||
            trimmed.contains("BEGIN PGP SIGNED MESSAGE") ||
            ZeroWidthEncoder.containsPayload(trimmed) ||
            (trimmed.length >= 32 && trimmed.matches(Regex("^[A-Za-z0-9+/=\\r\\n]+$")) &&
                !trimmed.contains(' '))
    }

    private fun renderBubbles(items: List<Pair<Rect, String>>) {
        val acs = service ?: return
        val host = acs.overlayWindowHost() ?: return
        val wm = host.windowManager
        val ui = host.context
        clearBubbles()
        for ((bounds, plain) in items) {
            val fingerprint = "${bounds.left},${bounds.top},${bounds.right},${plain.hashCode()}"
            val textView = TextView(ui).apply {
                this.text = plain
                setTextColor("#FFFFFFFF".toColorInt())
                setBackgroundColor("#CC1B5E20".toColorInt())
                textSize = 13f
                setPadding(16, 12, 16, 12)
                maxLines = 8
            }
            val container = FrameLayout(ui).apply {
                addView(textView)
                alpha = 0.92f
            }
            val params = WindowManager.LayoutParams(
                bounds.width().coerceAtLeast(120),
                WindowManager.LayoutParams.WRAP_CONTENT,
                WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
                WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_NOT_TOUCHABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                    WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS,
                PixelFormat.TRANSLUCENT,
            ).apply {
                gravity = Gravity.TOP or Gravity.START
                x = bounds.left
                y = bounds.top
            }
            try {
                wm.addView(container, params)
                bubbles += Bubble(container, fingerprint)
                Timber.d("Oversec bubble shown (%d chars)", plain.length)
            } catch (e: Exception) {
                Timber.w(e, "Failed to add decrypt bubble")
            }
        }
    }

    companion object {
        private const val MAX_BUBBLES = 8
    }
}
