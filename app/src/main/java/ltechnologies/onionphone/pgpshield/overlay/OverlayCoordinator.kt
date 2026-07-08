package ltechnologies.onionphone.pgpshield.overlay

/**
 * Drives the floating encrypt/decrypt overlay attached to the accessibility service.
 *
 * The coordinator tracks the foreground app and focused editable field, renders
 * the overlay buttons, and performs in-place encode/decode of field text using
 * the configured [EncodingMethod] (zero-width, padding, GPG, symmetric, Base64).
 */

import android.accessibilityservice.AccessibilityService
import android.content.ActivityNotFoundException
import ltechnologies.onionphone.pgpshield.util.SensitiveClipboard
import android.content.Intent
import android.graphics.PixelFormat
import android.os.Bundle
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import android.view.Gravity
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.Toast
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.data.db.OverlayAppConfigEntity
import ltechnologies.onionphone.pgpshield.data.db.OverlayConfigDao
import ltechnologies.onionphone.pgpshield.data.db.PaddingTemplateDao
import ltechnologies.onionphone.pgpshield.encoding.Base64Encoder
import ltechnologies.onionphone.pgpshield.encoding.EncodingMethod
import ltechnologies.onionphone.pgpshield.encoding.EncodingRegistry
import ltechnologies.onionphone.pgpshield.encoding.PaddingEncoder
import ltechnologies.onionphone.pgpshield.encoding.SymmetricEncoder
import ltechnologies.onionphone.pgpshield.encoding.ZeroWidthEncoder
import ltechnologies.onionphone.pgpshield.util.KeyIdParser
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.sync.Mutex
import timber.log.Timber

/**
 * Singleton that mediates between the accessibility service and the overlay UI.
 *
 * It holds the currently attached [AccessibilityService], the active
 * [FocusTarget], and serializes overlay actions through a mutex with a minimum
 * gap to avoid double-fires. All crypto runs off the main thread; cached
 * passphrases are read from [OverlayPassphraseSession] and wiped after use.
 */
@Singleton
class OverlayCoordinator @Inject constructor(
    private val overlayConfigDao: OverlayConfigDao,
    private val keyRepository: KeyRepository,
    private val cryptoOperations: CryptoOperations,
    private val paddingTemplateDao: PaddingTemplateDao,
    private val settingsRepository: SettingsRepository,
    private val passphraseSession: OverlayPassphraseSession,
) {
    private data class FocusTarget(
        val node: android.view.accessibility.AccessibilityNodeInfo,
        val windowId: Int,
        val viewId: String?,
    )

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val paddingEncoder = PaddingEncoder()
    private val symmetricEncoder = SymmetricEncoder()
    private val actionMutex = Mutex()
    private var lastActionAtMs = 0L
    private val minActionGapMs = 350L
    private var service: AccessibilityService? = null
    private var overlayContainer: FrameLayout? = null
    private var currentPackage: String? = null
    private var focusTarget: FocusTarget? = null
    private var uiStatus by mutableStateOf("Ready")

    /** Binds the live [AccessibilityService] used to render and act on the overlay. */
    fun attachService(acs: AccessibilityService) {
        service = acs
    }

    /** Removes the overlay and detaches the service (e.g. on service destroy). */
    fun detachService() {
        hideAll()
        service = null
    }

    /** Returns `true` when there is a currently tracked editable focus target. */
    fun hasFocusTarget(): Boolean = focusTarget != null

    /**
     * Reacts to a foreground app change by showing or hiding the overlay based on
     * the per-app configuration and global settings.
     */
    fun onForegroundAppChanged(packageName: String) {
        currentPackage = packageName
        scope.launch {
            if (!settingsRepository.current().overlayGloballyEnabled) {
                hideAll()
                return@launch
            }
            val config = overlayConfigDao.get(packageName) ?: overlayConfigDao.get("*")
            if (config?.enabled == true && settingsRepository.current().showOverlayButtons) {
                showButtons(config)
            } else {
                hideAll()
            }
        }
    }

    /**
     * Rescans the accessibility tree from [root] to (re)locate the best editable
     * field and update the tracked focus target.
     */
    fun refreshFocusedFieldFromRoot(root: AccessibilityNodeInfo?) {
        if (root == null) return
        findBestEditableNode(root)?.let { best ->
            onEditableFieldFocused(best)
            best.recycle()
        }
    }

    /** Removes the overlay window and releases the tracked focus node. */
    fun hideAll() {
        val wm = service?.getSystemService(WindowManager::class.java) ?: return
        overlayContainer?.let {
            try {
                wm.removeView(it)
            } catch (_: Exception) {
            }
        }
        overlayContainer = null
        focusTarget?.node?.recycle()
        focusTarget = null
    }

    private fun showButtons(config: OverlayAppConfigEntity) {
        val acs = service ?: return
        hideAll()
        val wm = acs.getSystemService(WindowManager::class.java)
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            WindowManager.LayoutParams.TYPE_ACCESSIBILITY_OVERLAY,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN,
            PixelFormat.TRANSLUCENT,
        ).apply {
            gravity = Gravity.END or Gravity.CENTER_VERTICAL
        }

        val textSp = config.overlayTextSizeSp
        val composeView = ComposeView(acs).apply {
            setContent {
                androidx.compose.foundation.layout.Column(Modifier.padding(4.dp)) {
                    Button(onClick = { encryptFocusedField() }, modifier = Modifier.padding(2.dp)) {
                        Text("Encrypt", fontSize = textSp.sp)
                    }
                    Button(onClick = { decryptFocusedField() }, modifier = Modifier.padding(2.dp)) {
                        Text("Decrypt", fontSize = textSp.sp)
                    }
                    Button(onClick = { copyFocusedField() }, modifier = Modifier.padding(2.dp)) {
                        Text("Copy", fontSize = textSp.sp)
                    }
                    Text(uiStatus, fontSize = (textSp - 1f).coerceAtLeast(10f).sp, modifier = Modifier.padding(2.dp))
                    Button(onClick = { hideAll() }, modifier = Modifier.padding(2.dp)) {
                        Text("Hide", fontSize = (textSp + 1f).sp)
                    }
                }
            }
        }
        val container = FrameLayout(acs)
        container.alpha = config.overlayAlpha
        container.addView(composeView)
        wm.addView(container, params)
        overlayContainer = container
    }

    private fun encryptFocusedField() {
        scope.launch {
            runOverlayAction(isEncrypt = true, fromAutoSend = false)
        }
    }

    /**
     * Handles a click that may be a "send" action; when auto-send is configured
     * and [node] looks like a send control, encrypts the focused field first.
     */
    fun onPotentialSendAction(node: android.view.accessibility.AccessibilityNodeInfo) {
        val pkg = currentPackage ?: return
        scope.launch {
            try {
                val config = overlayConfigDao.get(pkg) ?: return@launch
                if (!config.enabled || config.autoMode != "auto_send") return@launch
                if (!looksLikeSendAction(node)) return@launch
                runOverlayAction(isEncrypt = true, fromAutoSend = true)
            } finally {
                node.recycle()
            }
        }
    }

    private suspend fun runOverlayAction(isEncrypt: Boolean, fromAutoSend: Boolean) {
        if (!actionMutex.tryLock()) {
            setStatus("Busy…")
            return
        }
        try {
            val now = SystemClock.elapsedRealtime()
            if (now - lastActionAtMs < minActionGapMs) return
            lastActionAtMs = now

            var target = validTargetOrNull()
            if (target == null) {
                refreshFocusedFieldFromRoot(service?.rootInActiveWindow)
                target = validTargetOrNull()
            }
            if (target == null) {
                setStatus("No active editable field")
                return
            }
            val node = target.node
            val text = node.text?.toString()
            if (text.isNullOrBlank()) {
                setStatus("Field empty")
                return
            }
            val pkg = currentPackage ?: return
            val config = overlayConfigDao.get(pkg) ?: return
            val method = EncodingRegistry.parseId(config.encodingMethod)
            if (isEncrypt && method == EncodingMethod.ZERO_WIDTH) {
                val visible = ZeroWidthEncoder.stripInvisible(text)
                if (visible.length < config.minDecoyChars) {
                    setStatus("Decoy too short (${visible.length}/${config.minDecoyChars})")
                }
            }
            val result = withContext(Dispatchers.Default) {
                if (isEncrypt) {
                    encodeText(text, config, method)
                } else {
                    decodeTextSmart(text, config, method)
                }
            }
            if (result == null) {
                setStatus(if (isEncrypt) "Encrypt failed" else "Decrypt failed")
                return
            }
            if (config.requireConfirmBeforeSetText && !fromAutoSend) {
                setStatus("Tap again to apply")
                applyOutput(node, result, config, onlyClipboard = true)
                return
            }
            applyOutput(node, result, config, onlyClipboard = false)
            setStatus(if (isEncrypt) "Encrypted (${EncodingRegistry.toId(method)})" else "Decrypted")
            if (config.showResultToast) {
                toast(if (isEncrypt) "Overlay encrypted" else "Overlay decrypted")
            }
        } finally {
            actionMutex.unlock()
        }
    }

    private fun decryptFocusedField() {
        scope.launch {
            runOverlayAction(isEncrypt = false, fromAutoSend = false)
        }
    }

    private suspend fun encodeText(text: String, config: OverlayAppConfigEntity, method: EncodingMethod): String? =
        when (method) {
            EncodingMethod.ZERO_WIDTH ->
                ZeroWidthEncoder.encode(text, visiblePrefix = ZeroWidthEncoder.stripInvisible(text))
            EncodingMethod.PADDING -> {
                val templates = paddingTemplateDao.observeAll().first()
                val template = config.paddingTemplateId?.let { id ->
                    templates.firstOrNull { it.templateId == id }
                } ?: templates.firstOrNull()
                if (template == null) text
                else paddingEncoder.encode(text, template.title, template.content)
            }
            EncodingMethod.GPG -> gpgEncode(text, config)
            EncodingMethod.SYMMETRIC -> symmetricEncode(text, config)
            EncodingMethod.BASE64 -> Base64Encoder.encode(text)
        }

    private suspend fun decodeText(text: String, config: OverlayAppConfigEntity, method: EncodingMethod): String? =
        when (method) {
            EncodingMethod.ZERO_WIDTH -> ZeroWidthEncoder.decode(text)
            EncodingMethod.PADDING -> {
                val templates = paddingTemplateDao.observeAll().first()
                val template = config.paddingTemplateId?.let { id ->
                    templates.firstOrNull { it.templateId == id }
                } ?: templates.firstOrNull()
                if (template == null) null
                else paddingEncoder.decode(text, template.title, template.content)
            }
            EncodingMethod.GPG -> gpgDecode(text, config)
            EncodingMethod.SYMMETRIC -> symmetricDecode(text, config)
            EncodingMethod.BASE64 -> Base64Encoder.decode(text)
        }

    private suspend fun decodeTextSmart(
        text: String,
        config: OverlayAppConfigEntity,
        selected: EncodingMethod,
    ): String? {
        decodeText(text, config, selected)?.let { return it }
        if (config.autoMode != "suggest") return null
        val fallbackOrder = guessFallbackOrder(text).filterNot { it == selected }
        for (method in fallbackOrder) {
            decodeText(text, config, method)?.let {
                setStatus("Parsed via ${EncodingRegistry.toId(method)}")
                return it
            }
        }
        return null
    }

    private suspend fun gpgEncode(text: String, config: OverlayAppConfigEntity): String? {
        val recipientIds = buildList {
            config.encryptKeyId?.let { add(it) }
            addAll(KeyIdParser.parseCsv(config.recipientKeyIds))
        }.distinct()
        val publicKeys = withContext(Dispatchers.IO) {
            recipientIds.mapNotNull { keyRepository.getArmoredPublic(it) }
        }
        if (publicKeys.isEmpty()) {
            Timber.w("Overlay GPG: no recipient keys configured")
            return null
        }
        return String(
            cryptoOperations.encrypt(text.toByteArray(Charsets.UTF_8), publicKeys).ciphertext,
            Charsets.UTF_8,
        )
    }

    private suspend fun gpgDecode(text: String, config: OverlayAppConfigEntity): String? {
        if (!text.contains("BEGIN PGP")) return null
        val keyId = config.decryptKeyId ?: return null
        val secret = withContext(Dispatchers.IO) { keyRepository.getArmoredSecret(keyId) } ?: return null
        var passphrase = passphraseSession.get(keyId)
        if (passphrase == null) {
            requestPassphrasePrompt(keyId)
            setStatus("Enter passphrase in prompt")
            return null
        }
        return try {
            val result = cryptoOperations.decrypt(text.toByteArray(Charsets.UTF_8), secret, passphrase)
            String(result.plaintext, Charsets.UTF_8)
        } catch (e: Exception) {
            passphraseSession.clear(keyId)
            setStatus("Wrong passphrase")
            null
        } finally {
            passphrase.fill('\u0000')
        }
    }

    private fun symmetricEncode(text: String, config: OverlayAppConfigEntity): String? {
        val keyId = config.decryptKeyId ?: return null
        var passphrase = passphraseSession.get(keyId)
        if (passphrase == null) {
            requestPassphrasePrompt(keyId)
            setStatus("Enter passphrase in prompt")
            return null
        }
        return try {
            symmetricEncoder.encode(text, passphrase)
        } finally {
            passphrase.fill('\u0000')
        }
    }

    private fun symmetricDecode(text: String, config: OverlayAppConfigEntity): String? {
        val keyId = config.decryptKeyId ?: return null
        var passphrase = passphraseSession.get(keyId)
        if (passphrase == null) {
            requestPassphrasePrompt(keyId)
            setStatus("Enter passphrase in prompt")
            return null
        }
        return try {
            symmetricEncoder.decode(text, passphrase)
        } finally {
            passphrase.fill('\u0000')
        }
    }

    private fun applyOutput(
        node: android.view.accessibility.AccessibilityNodeInfo,
        value: String,
        config: OverlayAppConfigEntity,
        onlyClipboard: Boolean,
    ) {
        val safeValue = sanitizeForInput(value)
        if (config.composeViaClipboard || onlyClipboard) {
            val acs = service ?: return
            SensitiveClipboard.copy(acs, "pgp-overlay", safeValue, clearAfterMs = 30_000L)
            setStatus("Copied (auto-clears)")
            return
        }
        if (!setNodeText(node, safeValue)) {
            // ponytail: fallback for apps rejecting ACTION_SET_TEXT
            val acs = service ?: return
            SensitiveClipboard.copy(acs, "pgp-overlay", safeValue, clearAfterMs = 30_000L)
            val pasted = node.performAction(AccessibilityNodeInfo.ACTION_PASTE)
            if (!pasted) {
                node.performAction(AccessibilityNodeInfo.ACTION_FOCUS)
                node.performAction(AccessibilityNodeInfo.ACTION_CLICK)
                node.performAction(AccessibilityNodeInfo.ACTION_LONG_CLICK)
                node.performAction(AccessibilityNodeInfo.ACTION_PASTE)
            }
        }
    }

    private fun setNodeText(node: android.view.accessibility.AccessibilityNodeInfo, value: String): Boolean {
        val args = Bundle()
        args.putCharSequence(
            AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
            value,
        )
        return node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args)
    }

    private fun copyFocusedField() {
        val node = validTargetOrNull()?.node ?: return
        val text = node.text?.toString().orEmpty()
        if (text.isBlank()) {
            setStatus("Nothing to copy")
            return
        }
        val acs = service ?: return
        SensitiveClipboard.copy(acs, "pgp-overlay-source", text, clearAfterMs = 30_000L)
        setStatus("Copied source text")
    }

    private fun validTargetOrNull(): FocusTarget? {
        val target = focusTarget ?: return null
        val node = target.node
        if (!node.refresh()) return null
        if (!node.isEditable || !node.isVisibleToUser) return null
        if (!(node.isFocused || node.isAccessibilityFocused)) return null
        if (node.windowId != target.windowId) return null
        if (!target.viewId.isNullOrBlank() && node.viewIdResourceName != target.viewId) return null
        return target
    }

    private fun setStatus(message: String) {
        uiStatus = message
        Timber.d("Overlay: %s", message)
    }

    private fun toast(message: String) {
        val acs = service ?: return
        Toast.makeText(acs, message, Toast.LENGTH_SHORT).show()
    }

    private fun requestPassphrasePrompt(keyId: Long) {
        val acs = service ?: return
        val intent = Intent(acs, OverlayPassphrasePromptActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            .putExtra(OverlayPassphrasePromptActivity.EXTRA_KEY_ID, keyId)
        try {
            acs.startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            Timber.w(e, "Overlay passphrase prompt unavailable")
        }
    }

    private fun looksLikeSendAction(node: android.view.accessibility.AccessibilityNodeInfo): Boolean {
        val text = node.text?.toString()?.lowercase().orEmpty()
        val desc = node.contentDescription?.toString()?.lowercase().orEmpty()
        val viewId = node.viewIdResourceName?.lowercase().orEmpty()
        val clickable = node.isClickable || node.isLongClickable
        if (!clickable) return false
        return listOf(text, desc, viewId).any {
            it.contains("send") ||
                it.contains("envoi") ||
                it.contains("submit") ||
                it.contains("publish") ||
                it.contains("reply") ||
                it.contains("message_send") ||
                it.contains("chat_send") ||
                it.contains("envoyer") ||
                it.contains("mandar") ||
                it.contains("enviar")
        }
    }

    private fun guessFallbackOrder(text: String): List<EncodingMethod> {
        val trimmed = text.trim()
        return when {
            trimmed.startsWith("-----BEGIN PGP MESSAGE-----") -> listOf(EncodingMethod.GPG, EncodingMethod.BASE64)
            trimmed.startsWith("-----BEGIN PGP SIGNED MESSAGE-----") -> listOf(EncodingMethod.GPG, EncodingMethod.ZERO_WIDTH)
            trimmed.startsWith("U2FsdGVkX1") -> listOf(EncodingMethod.SYMMETRIC, EncodingMethod.BASE64)
            ZeroWidthEncoder.stripInvisible(trimmed) != trimmed -> listOf(EncodingMethod.ZERO_WIDTH, EncodingMethod.PADDING)
            trimmed.matches(Regex("^[A-Za-z0-9+/=\\r\\n]+$")) -> listOf(
                EncodingMethod.BASE64,
                EncodingMethod.SYMMETRIC,
                EncodingMethod.GPG,
            )
            else -> listOf(
                EncodingMethod.ZERO_WIDTH,
                EncodingMethod.PADDING,
                EncodingMethod.BASE64,
                EncodingMethod.SYMMETRIC,
                EncodingMethod.GPG,
            )
        }
    }

    private fun sanitizeForInput(value: String): String {
        // ponytail: keep text input safe for IME/accessibility injection
        val noNull = value.replace("\u0000", "")
        return if (noNull.length > 200_000) noNull.take(200_000) else noNull
    }

    private fun findBestEditableNode(root: AccessibilityNodeInfo): AccessibilityNodeInfo? {
        val queue = ArrayDeque<AccessibilityNodeInfo>()
        queue.add(AccessibilityNodeInfo.obtain(root))
        var focusedMatch: AccessibilityNodeInfo? = null
        var firstEditable: AccessibilityNodeInfo? = null
        while (queue.isNotEmpty()) {
            val node = queue.removeFirst()
            try {
                if (node.isEditable && node.isVisibleToUser) {
                    if (firstEditable == null) firstEditable = AccessibilityNodeInfo.obtain(node)
                    if (node.isFocused || node.isAccessibilityFocused) {
                        focusedMatch?.recycle()
                        focusedMatch = AccessibilityNodeInfo.obtain(node)
                    }
                }
                for (i in 0 until node.childCount) {
                    node.getChild(i)?.let { queue.add(it) }
                }
            } finally {
                node.recycle()
            }
        }
        return focusedMatch ?: firstEditable
    }

    /**
     * Records [node] as the active editable target (copying it defensively) so
     * subsequent encrypt/decrypt actions operate on the right field.
     */
    fun onEditableFieldFocused(node: android.view.accessibility.AccessibilityNodeInfo) {
        focusTarget?.node?.recycle()
        focusTarget = FocusTarget(
            node = android.view.accessibility.AccessibilityNodeInfo.obtain(node),
            windowId = node.windowId,
            viewId = node.viewIdResourceName,
        )
        setStatus("Field ready")
    }
}
