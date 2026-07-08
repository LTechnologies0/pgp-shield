package ltechnologies.onionphone.pgpshield.encoding

/**
 * Zero-width steganographic text encoding (Oversec-compatible mapping).
 *
 * Embeds a length-prefixed UTF-8 payload in Unicode zero-width and variation-selector
 * code points, prefixed with a `PSH` magic header. Uses spread markers to reduce
 * detection of long invisible runs.
 */
object ZeroWidthEncoder {
    private const val MAGIC = "PSH"
    private val MAGIC_BYTES = MAGIC.toByteArray()
    private const val SPREAD = 30
    private const val MAX_PAYLOAD_BYTES = 1 * 1024 * 1024

    private val MAPPING = Array(256) { byte ->
        if (byte <= 0xF) {
            Character.toChars(0xFE00 + byte)
        } else {
            Character.toChars(0xE0100 + byte - 0x10)
        }
    }

    private val REVERSE_MAPPING: Map<Int, Int> = buildMap {
        for (i in MAPPING.indices) {
            val chars = MAPPING[i]
            when (chars.size) {
                1 -> put(chars[0].code, i)
                2 -> put(Character.toCodePoint(chars[0], chars[1]), i)
            }
        }
    }

    private val MAGIC_ZW: String by lazy {
        encodeBytes(MAGIC_BYTES, spread = 0)
    }

    /**
     * Encodes [plaintext] as invisible characters, optionally prefixed with visible decoy text.
     *
     * @param plaintext UTF-8 text to hide.
     * @param visiblePrefix Visible cover characters prepended before the invisible payload.
     * @param spread Insert a zero-width space every [spread] encoded bytes (0 disables).
     * @return Combined visible prefix plus zero-width encoded frame.
     */
    fun encode(plaintext: String, visiblePrefix: String = "", spread: Int = SPREAD): String {
        val payload = plaintext.toByteArray(Charsets.UTF_8)
        val framed = ByteArray(MAGIC_BYTES.size + 4 + payload.size)
        System.arraycopy(MAGIC_BYTES, 0, framed, 0, MAGIC_BYTES.size)
        framed[MAGIC_BYTES.size] = (payload.size shr 24).toByte()
        framed[MAGIC_BYTES.size + 1] = (payload.size shr 16).toByte()
        framed[MAGIC_BYTES.size + 2] = (payload.size shr 8).toByte()
        framed[MAGIC_BYTES.size + 3] = payload.size.toByte()
        System.arraycopy(payload, 0, framed, MAGIC_BYTES.size + 4, payload.size)
        return visiblePrefix + encodeBytes(framed, spread)
    }

    /**
     * Decodes a zero-width payload from [text], or `null` if magic, length, or mapping is invalid.
     */
    fun decode(text: String): String? {
        val start = text.indexOf(MAGIC_ZW)
        if (start < 0) return null
        val bytes = decodeBytes(text.substring(start)) ?: return null
        if (bytes.size < MAGIC_BYTES.size + 4) return null
        for (i in MAGIC_BYTES.indices) {
            if (bytes[i] != MAGIC_BYTES[i]) return null
        }
        val offset = MAGIC_BYTES.size
        val len = ((bytes[offset].toInt() and 0xFF) shl 24) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 8) or
            (bytes[offset + 3].toInt() and 0xFF)
        if (len < 0 || len > MAX_PAYLOAD_BYTES) return null
        val payloadStart = offset + 4
        if (payloadStart + len > bytes.size) return null
        return String(bytes, payloadStart, len, Charsets.UTF_8)
    }

    /**
     * Removes leading zero-width encoded bytes from [s], returning the first visible suffix.
     *
     * Used to strip steganographic prefixes before displaying message text.
     */
    fun stripInvisible(s: String): String {
        var off = 0
        return try {
            while (off < s.length) {
                val cp = s.codePointAt(off)
                if (!REVERSE_MAPPING.containsKey(cp)) break
                off = s.offsetByCodePoints(off, 1)
            }
            s.substring(off)
        } catch (_: IndexOutOfBoundsException) {
            ""
        }
    }

    private fun encodeBytes(data: ByteArray, spread: Int): String {
        val sb = StringBuilder()
        var sinceVisible = 0
        for (b in data) {
            val mapped = MAPPING[b.toInt() and 0xFF]
            sb.append(mapped)
            sinceVisible++
            if (spread > 0 && sinceVisible >= spread) {
                sb.append('\u200B') // zero-width space as spread marker
                sinceVisible = 0
            }
        }
        return sb.toString()
    }

    private fun decodeBytes(encoded: String): ByteArray? {
        val out = ArrayList<Byte>()
        var i = 0
        while (i < encoded.length) {
            val cp = encoded.codePointAt(i)
            i = encoded.offsetByCodePoints(i, 1)
            if (cp == '\u200B'.code) continue
            val value = REVERSE_MAPPING[cp] ?: return null
            out.add(value.toByte())
        }
        return out.toByteArray()
    }
}
