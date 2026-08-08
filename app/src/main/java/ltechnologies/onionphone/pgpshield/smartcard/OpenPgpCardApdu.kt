package ltechnologies.onionphone.pgpshield.smartcard

/**
 * OpenPGP Card APDU helpers (ISO 7816-4 / OpenPGP Card 3.4).
 */

import ltechnologies.onionphone.pgpshield.engine.OpenPgpCardInfo
import ltechnologies.onionphone.pgpshield.engine.PgpException

/** Low-level APDU transceiver (NFC IsoDep or USB CCID). */
fun interface ApduChannel {
    fun transceive(command: ByteArray): ByteArray
}

/** Builds and parses OpenPGP Card APDUs. */
object OpenPgpCardApdu {
    /** Partial AID for OpenPGP Card application. */
    val OPENPGP_AID = byteArrayOf(
        0xD2.toByte(), 0x76, 0x00, 0x01, 0x24, 0x01,
    )

    fun selectOpenPgp(): ByteArray =
        apdu(0x00, 0xA4, 0x04, 0x00, OPENPGP_AID)

    fun verifyPw1(pin: CharArray): ByteArray {
        val pinBytes = pin.concatToString().toByteArray(Charsets.UTF_8)
        return try {
            apdu(0x00, 0x20, 0x00, 0x81, pinBytes)
        } finally {
            pinBytes.fill(0)
        }
    }

    /** PSO:CDS — Compute Digital Signature over [hash] (already hashed). */
    fun psoComputeSignature(hash: ByteArray): ByteArray =
        apdu(0x00, 0x2A, 0x9E, 0x9A, hash)

    /** PSO:DECIPHER — decrypt session key material. */
    fun psoDecipher(cipher: ByteArray): ByteArray =
        apdu(0x00, 0x2A, 0x80, 0x86, cipher)

    fun getDataApplicationRelated(): ByteArray =
        apdu(0x00, 0xCA, 0x00, 0x6E, data = null, le = 0x00)

    fun apdu(
        cla: Int,
        ins: Int,
        p1: Int,
        p2: Int,
        data: ByteArray? = null,
        le: Int? = null,
    ): ByteArray {
        val out = ArrayList<Byte>(6 + (data?.size ?: 0))
        out.add(cla.toByte())
        out.add(ins.toByte())
        out.add(p1.toByte())
        out.add(p2.toByte())
        if (data != null) {
            out.add(data.size.toByte())
            data.forEach { out.add(it) }
        }
        if (le != null) {
            out.add(le.toByte())
        }
        return out.toByteArray()
    }

    fun requireSuccess(response: ByteArray, op: String): ByteArray {
        if (response.size < 2) throw PgpException("Smart card $op: empty response")
        val sw1 = response[response.size - 2].toInt() and 0xff
        val sw2 = response[response.size - 1].toInt() and 0xff
        if (sw1 != 0x90 || sw2 != 0x00) {
            throw PgpException("Smart card $op failed: SW=%02X%02X".format(sw1, sw2))
        }
        return response.copyOfRange(0, response.size - 2)
    }

    fun parseCardInfo(selectResponse: ByteArray, transport: String): OpenPgpCardInfo {
        val aidHex = OPENPGP_AID.joinToString("") { "%02X".format(it) }
        // SELECT FCI often ends with historical bytes; serial is in Application Related Data (tag 6E / 5F52).
        val serial = extractSerial(selectResponse)
        return OpenPgpCardInfo(
            aid = aidHex,
            serial = serial,
            hasSignKey = true,
            hasDecryptKey = true,
            hasAuthKey = true,
            transport = transport,
        )
    }

    /**
     * Parses Application Related Data (GET DATA 6E) for serial (tag 5F52) and key fingerprints
     * presence (tags C5/C6/C7 are historical; fingerprints live under B6/B8/A4 in newer cards).
     */
    fun parseApplicationRelated(data: ByteArray, transport: String): OpenPgpCardInfo {
        val aidHex = OPENPGP_AID.joinToString("") { "%02X".format(it) }
        val serial = findTag(data, byteArrayOf(0x5F, 0x52))?.joinToString("") { "%02X".format(it) }
            ?: extractSerial(data)
        val signFp = findTag(data, byteArrayOf(0xC5.toByte()))
        val decFp = findTag(data, byteArrayOf(0xC6.toByte()))
        val authFp = findTag(data, byteArrayOf(0xC7.toByte()))
        fun present(fp: ByteArray?): Boolean = fp != null && fp.any { it != 0.toByte() }
        return OpenPgpCardInfo(
            aid = aidHex,
            serial = serial,
            hasSignKey = present(signFp),
            hasDecryptKey = present(decFp),
            hasAuthKey = present(authFp),
            transport = transport,
        )
    }

    private fun extractSerial(bytes: ByteArray): String? {
        if (bytes.size < 4) return null
        return bytes.takeLast(4).joinToString("") { "%02X".format(it) }
    }

    /** Minimal BER-TLV finder for short-form tags (1–2 byte tag, 1-byte length). */
    fun findTag(data: ByteArray, tag: ByteArray): ByteArray? {
        var i = 0
        while (i + tag.size + 1 < data.size) {
            var match = true
            for (t in tag.indices) {
                if (data[i + t] != tag[t]) {
                    match = false
                    break
                }
            }
            if (match) {
                val len = data[i + tag.size].toInt() and 0xff
                val start = i + tag.size + 1
                if (start + len <= data.size) return data.copyOfRange(start, start + len)
            }
            i++
        }
        return null
    }
}

/**
 * Session helper wrapping [ApduChannel] for OpenPGP Card select / PIN / PSO.
 */
class OpenPgpCardSession(
    private val channel: ApduChannel,
    private val transport: String,
) {
    var info: OpenPgpCardInfo? = null
        private set

    fun select(): OpenPgpCardInfo {
        val resp = channel.transceive(OpenPgpCardApdu.selectOpenPgp())
        OpenPgpCardApdu.requireSuccess(resp, "SELECT")
        info = runCatching {
            val appRelated = channel.transceive(OpenPgpCardApdu.getDataApplicationRelated())
            val body = OpenPgpCardApdu.requireSuccess(appRelated, "GET DATA 6E")
            OpenPgpCardApdu.parseApplicationRelated(body, transport)
        }.getOrElse {
            OpenPgpCardApdu.parseCardInfo(resp, transport)
        }
        return info!!
    }

    fun verifyPin(pin: CharArray) {
        val resp = channel.transceive(OpenPgpCardApdu.verifyPw1(pin))
        OpenPgpCardApdu.requireSuccess(resp, "VERIFY PIN")
    }

    fun sign(hash: ByteArray): ByteArray {
        val resp = channel.transceive(OpenPgpCardApdu.psoComputeSignature(hash))
        return OpenPgpCardApdu.requireSuccess(resp, "PSO SIGN")
    }

    fun decrypt(cipher: ByteArray): ByteArray {
        val resp = channel.transceive(OpenPgpCardApdu.psoDecipher(cipher))
        return OpenPgpCardApdu.requireSuccess(resp, "PSO DECRYPT")
    }
}
