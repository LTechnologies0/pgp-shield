package ltechnologies.onionphone.pgpshield.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import ltechnologies.onionphone.pgpshield.engine.KeyRingReader
import ltechnologies.onionphone.pgpshield.engine.PgpAlgorithmPolicy
import java.util.Base64
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Parses and persists Autocrypt email-to-key mappings from message headers.
 *
 * Stores discovered `addr` → master key id associations in SharedPreferences when
 * valid `keydata` is present in `Autocrypt` or `Autocrypt-Gossip` headers.
 * Imports the public ring into [KeyRepository] so encrypt lookups can resolve material.
 * Honours [SettingsRepository.autocryptEnabled].
 */
@Singleton
class AutocryptManager @Inject constructor(
    @ApplicationContext context: Context,
    private val settingsRepository: SettingsRepository,
    private val keyRepository: KeyRepository,
) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val reader = KeyRingReader()

    /**
     * Processes Autocrypt headers from a map (e.g. MIME header names to values).
     *
     * Accepts both canonical and lowercase header names for `Autocrypt` and `Autocrypt-Gossip`.
     */
    suspend fun storeFromHeaders(headers: Map<String, String>) {
        if (!settingsRepository.current().autocryptEnabled) return
        val gossip = headers["Autocrypt-Gossip"] ?: headers["autocrypt-gossip"]
        val direct = headers["Autocrypt"] ?: headers["autocrypt"]
        parseAndStore(gossip)
        parseAndStore(direct)
    }

    /**
     * Processes raw header lines, extracting Autocrypt and Autocrypt-Gossip values.
     */
    suspend fun storeFromHeaderLines(lines: Iterable<String>) {
        if (!settingsRepository.current().autocryptEnabled) return
        for (line in lines) {
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
     * Lookup remains available even when Autocrypt ingest is disabled so existing peers work.
     */
    fun lookup(email: String): Long? =
        prefs.getLong(emailKey(email), -1L).takeIf { it >= 0L }

    /** Returns all stored email → key id mappings. */
    fun allMappings(): Map<String, Long> =
        prefs.all.mapNotNull { (k, v) ->
            if (!k.startsWith(KEY_PREFIX) || v !is Long) return@mapNotNull null
            k.removePrefix(KEY_PREFIX) to v
        }.toMap()

    /** Removes a single peer mapping. */
    fun remove(email: String) {
        prefs.edit().remove(emailKey(email)).apply()
    }

    private suspend fun parseAndStore(headerValue: String?) {
        if (headerValue.isNullOrBlank()) return
        val params = headerValue.split(';').associate { part ->
            val kv = part.trim().split('=', limit = 2)
            if (kv.size == 2) kv[0].trim().lowercase() to kv[1].trim().trim('"')
            else kv[0].trim().lowercase() to ""
        }
        val email = params["addr"]?.takeIf { it.isNotBlank() } ?: return
        val keydata = params["keydata"]?.takeIf { it.isNotBlank() } ?: return
        runCatching {
            withContext(Dispatchers.IO) {
                val keyBytes = if (keydata.contains("BEGIN PGP")) {
                    keydata.toByteArray(Charsets.UTF_8)
                } else {
                    // Autocrypt keydata is base64 of the binary transferable public key.
                    Base64.getDecoder().decode(keydata.replace(Regex("\\s+"), ""))
                }
                val info = reader.readPublicKeyRing(keyBytes.inputStream())
                PgpAlgorithmPolicy.validateKeyRing(info, allowRevoked = false, allowExpired = false)
                // Never replace an existing secret ring with a public-only Autocrypt import.
                if (keyRepository.getArmoredSecret(info.masterKeyId) == null) {
                    keyRepository.importKeyRing(keyBytes, secret = false)
                }
                prefs.edit().putLong(emailKey(email), info.masterKeyId).apply()
            }
        }
    }

    private fun emailKey(email: String) = KEY_PREFIX + email.lowercase()

    companion object {
        private const val PREFS_NAME = "pgp_shield_autocrypt"
        private const val KEY_PREFIX = "email:"
    }
}
