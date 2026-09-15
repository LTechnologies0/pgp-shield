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
 * Stores discovered `addr` → master key id associations in EncryptedSharedPreferences
 * (StrongBox-preferred MasterKey) when valid `keydata` is present in Autocrypt headers.
 * Imports the public ring into [KeyRepository] so encrypt lookups can resolve material.
 * Honours [SettingsRepository.autocryptEnabled].
 */
@Singleton
class AutocryptManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val settingsRepository: SettingsRepository,
    private val keyRepository: KeyRepository,
) {
    private val prefs by lazy { openSecurePrefs() }
    private val reader = KeyRingReader()

    private fun openSecurePrefs(): android.content.SharedPreferences {
        val (secure, _) = SecurePrefs.createOrReset(context, PREFS_NAME_SECURE)
        migratePlaintextIfNeeded(secure)
        return secure
    }

    /** One-shot copy from legacy plaintext prefs into Keystore-backed EncryptedSharedPreferences. */
    private fun migratePlaintextIfNeeded(secure: android.content.SharedPreferences) {
        val legacy = context.getSharedPreferences(PREFS_NAME_LEGACY, Context.MODE_PRIVATE)
        val all = legacy.all
        if (all.isEmpty()) return
        val editor = secure.edit()
        for ((key, value) in all) {
            when (value) {
                is Long -> editor.putLong(key, value)
                is Int -> editor.putLong(key, value.toLong())
                is String -> editor.putString(key, value)
                is Boolean -> editor.putBoolean(key, value)
            }
        }
        editor.apply()
        legacy.edit().clear().apply()
        timber.log.Timber.i("Migrated %d Autocrypt prefs into EncryptedSharedPreferences", all.size)
    }

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

    /**
     * Imports Autocrypt peer key material from the OpenPGP API
     * (`EXTRA_AUTOCRYPT_PEER_UPDATE` / `ACTION_UPDATE_AUTOCRYPT_PEER`).
     *
     * @return Master key id when imported or already present; `null` if skipped/failed.
     */
    suspend fun storePeerKeyData(
        email: String,
        keyData: ByteArray?,
        preferMutual: Boolean = false,
    ): Long? {
        if (!settingsRepository.current().autocryptEnabled) return lookup(email)
        if (keyData == null || keyData.isEmpty()) return lookup(email)
        val normalized = email.trim().lowercase()
        if (normalized.isEmpty() || !normalized.contains('@')) return null
        return runCatching {
            withContext(Dispatchers.IO) {
                val info = reader.readPublicKeyRing(keyData.inputStream())
                PgpAlgorithmPolicy.validateKeyRing(info, allowRevoked = false, allowExpired = false)
                if (keyRepository.getArmoredSecret(info.masterKeyId) == null) {
                    keyRepository.importKeyRing(keyData, secret = false)
                }
                prefs.edit()
                    .putLong(emailKey(normalized), info.masterKeyId)
                    .putBoolean(preferKey(normalized), preferMutual)
                    .apply()
                info.masterKeyId
            }
        }.getOrNull()
    }

    /** True when the peer last advertised Autocrypt prefer-encrypt=mutual. */
    fun prefersMutual(email: String): Boolean =
        prefs.getBoolean(preferKey(email.trim().lowercase()), false)

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
        // Autocrypt Level 1: only type=1 (or omitted, treated as 1). Ignore gossip/other.
        val type = params["type"]
        if (type != null && type != "1") return
        val preferMutual = params["prefer-encrypt"].equals("mutual", ignoreCase = true)
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
                prefs.edit()
                    .putLong(emailKey(email), info.masterKeyId)
                    .putBoolean(preferKey(email), preferMutual)
                    .apply()
            }
        }
    }

    private fun emailKey(email: String) = KEY_PREFIX + email.lowercase()

    private fun preferKey(email: String) = PREFER_PREFIX + email.lowercase()

    companion object {
        private const val PREFS_NAME_LEGACY = "pgp_shield_autocrypt"
        private const val PREFS_NAME_SECURE = "pgp_shield_autocrypt_enc"
        private const val KEY_PREFIX = "email:"
        private const val PREFER_PREFIX = "prefer_mutual:"
    }
}
