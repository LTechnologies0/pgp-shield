package ltechnologies.onionphone.pgpshield.util

/**
 * Best-effort zeroization of in-memory secret buffers.
 */

/** Overwrites char/byte buffers holding secrets so they cannot linger in memory. */
object SensitiveWiper {
    /** Fills each non-null [buffers] entry with NUL characters. */
    fun wipe(vararg buffers: CharArray?) {
        buffers.forEach { it?.fill('\u0000') }
    }

    /** Fills [bytes] with zeros when non-null. */
    fun wipe(bytes: ByteArray?) {
        bytes?.fill(0)
    }
}
