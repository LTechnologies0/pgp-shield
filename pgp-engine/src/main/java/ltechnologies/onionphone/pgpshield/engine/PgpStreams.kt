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
import org.bouncycastle.openpgp.PGPPBEEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator

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
        fingerprintCalculator: KeyFingerPrintCalculator = PgpFingerprints.calculator,
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

    /**
     * Lists PKESK recipient key ids and whether a SKESK (passphrase) packet is present.
     * Used by the OpenPGP API to skip passphrase UI when no local secret matches.
     */
    fun inspectEncryptedRecipients(
        data: ByteArray,
        fingerprintCalculator: KeyFingerPrintCalculator = PgpFingerprints.calculator,
    ): EncryptedRecipientInfo {
        val list = readEncryptedList(data, fingerprintCalculator)
        val pkeskIds = ArrayList<Long>()
        var hasPbe = false
        val iter = list.encryptedDataObjects
        while (iter.hasNext()) {
            when (val packet = iter.next()) {
                is PGPPublicKeyEncryptedData -> pkeskIds.add(packet.keyID)
                is PGPPBEEncryptedData -> hasPbe = true
            }
        }
        return EncryptedRecipientInfo(pkeskKeyIds = pkeskIds, hasPassphraseSession = hasPbe)
    }
}

/** PKESK / SKESK summary for decrypt preflight. */
data class EncryptedRecipientInfo(
    val pkeskKeyIds: List<Long>,
    val hasPassphraseSession: Boolean,
)
