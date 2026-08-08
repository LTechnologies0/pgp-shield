package ltechnologies.onionphone.pgpshield.ui.crypto

/**
 * Privacy-friendly formatting for [ltechnologies.onionphone.pgpshield.engine.CryptoResourceSummary].
 * Never includes payloads or key material — only durations and heap delta.
 */

import android.content.Context
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.engine.CryptoOperation
import ltechnologies.onionphone.pgpshield.engine.CryptoResourceSummary
import ltechnologies.onionphone.pgpshield.engine.CryptoStage

object CryptoProgressLabels {
    fun operationLabel(context: Context, op: CryptoOperation): String =
        context.getString(
            when (op) {
                CryptoOperation.ENCRYPT, CryptoOperation.ENCRYPT_MANY -> R.string.crypto_op_encrypt
                CryptoOperation.DECRYPT -> R.string.crypto_op_decrypt
                CryptoOperation.SIGN -> R.string.crypto_op_sign
                CryptoOperation.VERIFY -> R.string.crypto_op_verify
                CryptoOperation.KEYGEN -> R.string.crypto_op_keygen
                CryptoOperation.CHANGE_PASSPHRASE -> R.string.crypto_op_passphrase
                CryptoOperation.ADD_SUBKEY -> R.string.crypto_op_subkey
                CryptoOperation.OTHER -> R.string.crypto_op_other
            },
        )

    fun stageLabel(context: Context, stage: CryptoStage): String =
        context.getString(
            when (stage) {
                CryptoStage.IDLE -> R.string.crypto_stage_idle
                CryptoStage.PREPARE -> R.string.crypto_stage_prepare
                CryptoStage.PARSE_KEYS -> R.string.crypto_stage_parse_keys
                CryptoStage.GENERATE_KEY_PAIRS -> R.string.crypto_stage_generate_pairs
                CryptoStage.S2K_PROTECT -> R.string.crypto_stage_s2k
                CryptoStage.UNLOCK_SECRET -> R.string.crypto_stage_unlock
                CryptoStage.BUILD_LITERAL -> R.string.crypto_stage_literal
                CryptoStage.ENCRYPT_SESSION -> R.string.crypto_stage_encrypt
                CryptoStage.DECRYPT_PAYLOAD -> R.string.crypto_stage_decrypt
                CryptoStage.VERIFY_MDC -> R.string.crypto_stage_mdc
                CryptoStage.SIGN -> R.string.crypto_stage_sign
                CryptoStage.VERIFY_SIGNATURE -> R.string.crypto_stage_verify
                CryptoStage.ARMOR -> R.string.crypto_stage_armor
                CryptoStage.DONE -> R.string.crypto_stage_done
            },
        )

    fun summaryLine(context: Context, summary: CryptoResourceSummary): String {
        val op = operationLabel(context, summary.operation)
        val heap = formatHeapDelta(summary.heapDeltaBytes)
        return context.getString(R.string.crypto_resource_summary_fmt, op, summary.totalMs, heap)
    }

    private fun formatHeapDelta(bytes: Long): String {
        val abs = kotlin.math.abs(bytes)
        val mb = abs / (1024.0 * 1024.0)
        val sign = if (bytes >= 0) "+" else "−"
        return if (mb >= 0.1) {
            "%s%.1f MB".format(sign, mb)
        } else {
            "%s%d KB".format(sign, (abs / 1024L).coerceAtLeast(0L))
        }
    }
}
