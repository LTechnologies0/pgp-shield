package ltechnologies.onionphone.pgpshield.engine

/**
 * Applies optional OpenPGP ASCII-armor headers (openpgp-api EXTRA_CUSTOM_HEADERS).
 */

import org.bouncycastle.bcpg.ArmoredOutputStream

/** Helpers for [ArmoredOutputStream.setHeader]. */
object ArmorHeaders {
    fun apply(armor: ArmoredOutputStream, headers: Map<String, String>) {
        for ((name, value) in headers) {
            if (name.isBlank()) continue
            armor.setHeader(name.trim(), value)
        }
    }

    /**
     * Parses openpgp-api style header lines (`"Name: value"`) into a map.
     * Lines without `:` are skipped.
     */
    fun fromHeaderLines(lines: List<String>?): Map<String, String> {
        if (lines.isNullOrEmpty()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (raw in lines) {
            val line = raw.trim()
            if (line.isEmpty()) continue
            val sep = line.indexOf(':')
            if (sep <= 0) continue
            val name = line.substring(0, sep).trim()
            val value = line.substring(sep + 1).trim()
            if (name.isNotEmpty()) out[name] = value
        }
        return out
    }
}
