package ltechnologies.onionphone.pgpshield.engine

/**
 * Bounded stream I/O for OpenPGP message processing.
 *
 * Prevents unbounded memory consumption when reading literal data or decrypted payloads.
 */

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream

/** Size-limited stream copy and read utilities. */
object PgpIo {
    /** Maximum bytes allowed when reading or copying streams (64 MiB). */
    const val MAX_STREAM_BYTES: Long = 64L * 1024 * 1024

    /**
     * Copies [input] to [output] up to [maxBytes].
     *
     * @return Total bytes copied.
     * @throws PgpException if the limit is exceeded.
     */
    fun copyLimited(input: InputStream, output: OutputStream, maxBytes: Long = MAX_STREAM_BYTES): Long {
        val buffer = ByteArray(8192)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            if (total > maxBytes) {
                throw PgpException("Input exceeds maximum allowed size ($maxBytes bytes)")
            }
            output.write(buffer, 0, read)
        }
        return total
    }

    /**
     * Reads all bytes from [input] up to [maxBytes].
     *
     * @throws PgpException if the stream exceeds [maxBytes].
     */
    fun readLimited(input: InputStream, maxBytes: Long = MAX_STREAM_BYTES): ByteArray {
        val buffer = ByteArray(8192)
        val out = ByteArrayOutputStream()
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read
            if (total > maxBytes) {
                throw PgpException("Input exceeds maximum allowed size ($maxBytes bytes)")
            }
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }
}
