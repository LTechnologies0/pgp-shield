package ltechnologies.onionphone.pgpshield.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import ltechnologies.onionphone.pgpshield.engine.KeyRingReader
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Parses and persists Autocrypt email-to-key mappings from message headers.
 *
 * Stores discovered `addr` → master key id associations in SharedPreferences when
 * valid `keydata` is present in `Autocrypt` or `Autocrypt-Gossip` headers.
 */
@Singleton
class AutocryptManager @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val reader = KeyRingReader()

    /**
     * Processes Autocrypt headers from a map (e.g. MIME header names to values).
     *
     * Accepts both canonical and lowercase header names for `Autocrypt` and `Autocrypt-Gossip`.
     */
    fun storeFromHeaders(headers: Map<String, String>) {
        val gossip = headers["Autocrypt-Gossip"] ?: headers["autocrypt-gossip"]
        val direct = headers["Autocrypt"] ?: headers["autocrypt"]
        parseAndStore(gossip)
        parseAndStore(direct)
    }

    /**
     * Processes raw header lines, extracting Autocrypt and Autocrypt-Gossip values.
     */
    fun storeFromHeaderLines(lines: Iterable<String>) {
        lines.forEach { line ->
            val trimmed = line.trim()
            when {
                trimmed.startsWith("Autocrypt-Gossip:", ignoreCase = true) ->
                    parseAndStore(trimmed.substringAfter(':'))
                trimmed.startsWith("Autocrypt:", ignoreCase = true) ->
                    parseAndStore(trimmed.substringAfter(':'))
            }
        }
    }

    /**
     * Returns the master key id previously associated with [email], if any.
     */
    fun lookup(email: String): Long? =
        prefs.getLong(emailKey(email), -1L).takeIf { it >= 0L }

    /** Returns all stored email → key id mappings. */
    fun allMappings(): Map<String, Long> =
        prefs.all.mapNotNull { (k, v) ->
            if (!k.startsWith(KEY_PREFIX) || v !is Long) return@mapNotNull null
            k.removePrefix(KEY_PREFIX) to v
        }.toMap()

    private fun parseAndStore(headerValue: String?) {
        if (headerValue.isNullOrBlank()) return
        val params = headerValue.split(';').associate { part ->
            val kv = part.trim().split('=', limit = 2)
            if (kv.size == 2) kv[0].trim().lowercase() to kv[1].trim().trim('"')
            else kv[0].trim().lowercase() to ""
        }
        val email = params["addr"]?.takeIf { it.isNotBlank() } ?: return
        val keydata = params["keydata"]?.takeIf { it.isNotBlank() } ?: return
        val armored = if (keydata.contains("BEGIN PGP")) {
            keydata.toByteArray(Charsets.UTF_8)
        } else {
            // ponytail: base64 armored key in header without BEGIN line
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n$keydata\n-----END PGP PUBLIC KEY BLOCK-----"
                .toByteArray(Charsets.UTF_8)
        }
        runCatching {
            val info = reader.readPublicKeyRing(armored.inputStream())
            prefs.edit().putLong(emailKey(email), info.masterKeyId).apply()
        }
    }

    private fun emailKey(email: String) = KEY_PREFIX + email.lowercase()

    companion object {
        private const val PREFS_NAME = "pgp_shield_autocrypt"
        private const val KEY_PREFIX = "email:"
    }
}
