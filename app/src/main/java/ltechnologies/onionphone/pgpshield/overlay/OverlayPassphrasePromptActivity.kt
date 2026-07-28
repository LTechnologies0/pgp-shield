package ltechnologies.onionphone.pgpshield.overlay

/**
 * Standalone activity that prompts for a key passphrase on behalf of the overlay.
 *
 * Uses a classic [android.widget.EditText] (not Compose TextField) so IME input,
 * autofill, and accessibility SET_TEXT all update the value reliably.
 */

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.ComponentActivity
import androidx.activity.enableEdgeToEdge
import androidx.core.view.setPadding
import dagger.hilt.android.AndroidEntryPoint
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.util.WindowSecureHelper
import javax.inject.Inject

/**
 * Secure, screenshot-protected passphrase entry screen launched by the overlay.
 *
 * On successful entry it stores the passphrase into [OverlayPassphraseSession]
 * keyed by the requested key id (passed via [EXTRA_KEY_ID]), zeroes the local
 * buffer and finishes with `RESULT_OK`.
 */
@AndroidEntryPoint
class OverlayPassphrasePromptActivity : ComponentActivity() {
    @Inject lateinit var session: OverlayPassphraseSession
    @Inject lateinit var settingsRepository: SettingsRepository

    /** Reads the target key id, binds screenshot policy and renders the prompt UI. */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        WindowSecureHelper.bind(this, settingsRepository)
        val keyId = intent.getLongExtra(EXTRA_KEY_ID, -1L)
        if (keyId < 0L) {
            finish()
            return
        }
        // Automation / instrumentation can unlock without IME quirks.
        intent.getStringExtra(EXTRA_PASSPHRASE)?.takeIf { it.isNotBlank() }?.let { prefill ->
            session.put(keyId, prefill.toCharArray())
            setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_KEY_ID, keyId))
            finish()
            return
        }
        enableEdgeToEdge()

        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad)
            gravity = Gravity.TOP
        }
        root.addView(
            TextView(this).apply {
                text = getString(R.string.overlay_passphrase_title)
                textSize = 20f
                setPadding(0, 0, 0, pad)
            },
        )
        val field = EditText(this).apply {
            hint = getString(R.string.crypto_key_passphrase)
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_YES
        }
        root.addView(
            field,
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ),
        )
        root.addView(
            Button(this).apply {
                text = getString(R.string.overlay_unlock)
                setOnClickListener {
                    val chars = field.text?.toString()?.toCharArray() ?: return@setOnClickListener
                    if (chars.isEmpty()) return@setOnClickListener
                    field.text?.clear()
                    session.put(keyId, chars)
                    chars.fill('\u0000')
                    setResult(Activity.RESULT_OK, Intent().putExtra(EXTRA_KEY_ID, keyId))
                    finish()
                }
            },
            LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            ).also { it.topMargin = pad },
        )
        setContentView(root)
        field.requestFocus()
    }

    /** Intent extras for launching the prompt. */
    companion object {
        /** Long extra carrying the master key id whose passphrase is requested. */
        const val EXTRA_KEY_ID = "overlay_key_id"

        /** Optional passphrase for automated unlock (ADB / instrumentation). */
        const val EXTRA_PASSPHRASE = "overlay_passphrase"
    }
}
