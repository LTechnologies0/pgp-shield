package ltechnologies.onionphone.pgpshield.api

import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/** Short-lived service-side passphrase cache keyed by caller package + token. */
@Singleton
class ApiPassphraseCache @Inject constructor() {
    private data class Entry(val passphrase: CharArray, val token: String, val expiresAtMs: Long)

    private val entries = ConcurrentHashMap<String, Entry>()
    private val ttlMs = 2 * 60 * 1000L

    fun put(packageName: String, passphrase: CharArray): String {
        clear(packageName)
        val token = UUID.randomUUID().toString()
        entries[packageName] = Entry(passphrase.copyOf(), token, System.currentTimeMillis() + ttlMs)
        return token
    }

    fun peek(packageName: String, token: String?): CharArray? {
        val entry = entries[packageName] ?: return null
        if (entry.expiresAtMs <= System.currentTimeMillis()) {
            clear(packageName)
            return null
        }
        if (token.isNullOrBlank() || token != entry.token) return null
        return entry.passphrase.copyOf()
    }

    fun clear(packageName: String) {
        entries.remove(packageName)?.passphrase?.fill('\u0000')
    }
}
