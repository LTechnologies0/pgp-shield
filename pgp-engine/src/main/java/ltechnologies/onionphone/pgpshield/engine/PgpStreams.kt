package ltechnologies.onionphone.pgpshield.engine

/**
 * Low-level OpenPGP stream helpers.
 *
 * Decodes armored or binary packets and locates encrypted-data lists inside messages.
 */

import java.io.ByteArrayInputStream
import java.io.InputStream
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/** Utilities for decoding OpenPGP packet streams. */
object PgpStreams {
    /** Returns a decoder stream that unwraps ASCII armor when present. */
    fun decoderStream(data: ByteArray): InputStream =
        PGPUtil.getDecoderStream(ByteArrayInputStream(data))

    /**
     * Scans [data] for the first [PGPEncryptedDataList] packet.
     *
     * @throws PgpException if no encrypted data is found.
     */
    fun readEncryptedList(
        data: ByteArray,
        fingerprintCalculator: JcaKeyFingerprintCalculator,
    ): PGPEncryptedDataList {
        decoderStream(data).use { stream ->
            val factory = PGPObjectFactory(stream, fingerprintCalculator)
            var obj = factory.nextObject()
            while (obj != null) {
                if (obj is PGPEncryptedDataList) return obj
                obj = factory.nextObject()
            }
        }
        throw PgpException("No encrypted data in message")
    }
}
