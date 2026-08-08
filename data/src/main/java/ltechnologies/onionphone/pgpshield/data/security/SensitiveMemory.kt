package ltechnologies.onionphone.pgpshield.data.security

/**
 * Best-effort zeroization of secret buffers used during crypto operations.
 *
 * Does not prevent JVM/GC copies of immutable [String]s — prefer [CharArray]/[ByteArray]
 * for secrets and wipe them in `finally` blocks.
 */
object SensitiveMemory {
    /** Overwrites each non-null char buffer with NUL. */
    fun wipe(vararg buffers: CharArray?) {
        buffers.forEach { it?.fill('\u0000') }
    }

    /** Overwrites each non-null byte buffer with zeros. */
    fun wipe(vararg buffers: ByteArray?) {
        buffers.forEach { it?.fill(0) }
    }

    /**
     * Runs [block] with [secret], then wipes [secret] (and optional [extras]) in `finally`.
     */
    inline fun <T> useAndWipe(
        secret: CharArray,
        vararg extras: CharArray?,
        block: (CharArray) -> T,
    ): T {
        try {
            return block(secret)
        } finally {
            wipe(secret, *extras)
        }
    }
}
