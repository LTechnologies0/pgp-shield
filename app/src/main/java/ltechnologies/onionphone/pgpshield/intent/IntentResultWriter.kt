package ltechnologies.onionphone.pgpshield.intent

/**
 * Computes output filenames and writes intent results back to the caller.
 */

import android.app.Activity
import android.content.Intent
import java.io.File

/** Helper for naming, writing and finalizing Intent-based crypto results. */
object IntentResultWriter {
    /** Returns the `.gpg` output name for an encrypted [sourceFileName]. */
    fun gpgOutputName(sourceFileName: String): String = "$sourceFileName.gpg"

    /** Strips a known `.gpg`/`.pgp`/`.asc` suffix to derive the decrypted name. */
    fun decryptedOutputName(encryptedFileName: String): String {
        val lower = encryptedFileName.lowercase()
        return when {
            lower.endsWith(".gpg") -> encryptedFileName.dropLast(4)
            lower.endsWith(".pgp") -> encryptedFileName.dropLast(4)
            lower.endsWith(".asc") -> encryptedFileName.dropLast(4)
            else -> encryptedFileName
        }
    }

    /**
     * Writes [ciphertext] next to (or into the caller's output path for) the
     * source file, optionally deleting the plaintext source, and returns the file.
     */
    fun writeEncryptedForCaller(
        intent: Intent,
        sourcePath: String,
        ciphertext: ByteArray,
    ): File {
        val source = File(sourcePath)
        val outDir = intent.getStringExtra(PgpIntentActions.EXTRA_OUTPUT_PATH)?.let(::File)
            ?: source.parentFile
            ?: error("No output directory")
        val outFile = File(outDir, gpgOutputName(source.name))
        outFile.writeBytes(ciphertext)
        if (intent.getBooleanExtra(PgpIntentActions.EXTRA_DELETE_SOURCE, false)) {
            source.delete()
        }
        return outFile
    }

    /**
     * Writes [plaintext] to the derived output location, optionally deleting the
     * encrypted source, and returns the written file.
     */
    fun writeDecryptedForCaller(
        intent: Intent,
        sourcePath: String,
        plaintext: ByteArray,
    ): File {
        val source = File(sourcePath)
        val outDir = intent.getStringExtra(PgpIntentActions.EXTRA_OUTPUT_PATH)?.let(::File)
            ?: source.parentFile
            ?: error("No output directory")
        val outFile = File(outDir, decryptedOutputName(source.name))
        outFile.writeBytes(plaintext)
        if (intent.getBooleanExtra(PgpIntentActions.EXTRA_DELETE_SOURCE, false)) {
            source.delete()
        }
        return outFile
    }

    /** Sets `RESULT_OK` and finishes [activity]. */
    fun finishOk(activity: Activity) {
        activity.setResult(Activity.RESULT_OK)
        activity.finish()
    }

    /** Sets `RESULT_CANCELED` and finishes [activity]. */
    fun finishCancel(activity: Activity) {
        activity.setResult(Activity.RESULT_CANCELED)
        activity.finish()
    }

    /** Returns `true` when the intent carries integration source paths (e.g. SFM). */
    fun isCallerIntegration(intent: Intent): Boolean =
        !intent.getStringArrayListExtra(PgpIntentActions.EXTRA_SOURCE_PATHS).isNullOrEmpty()
}
