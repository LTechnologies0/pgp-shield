package ltechnologies.onionphone.pgpshield.overlay

/**
 * Short-lived, bounded in-memory cache of unlocked passphrases for the overlay.
 */

import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Caches decrypted passphrases per key id with a TTL and a hard capacity so the
 * overlay can decrypt repeatedly without re-prompting, while limiting exposure.
 *
 * Entries expire after a fixed TTL and the oldest is evicted past the capacity
 * limit. All stored buffers are zeroed on removal.
 */
@Singleton
class OverlayPassphraseSession @Inject constructor() {
    private data class Entry(val passphrase: CharArray, val expiresAtMs: Long)

    private val entries = ConcurrentHashMap<Long, Entry>()
    private val ttlMs: Long = 2 * 60 * 1000L
    private val maxEntries = 3

    /**
     * Returns a defensive copy of the cached passphrase for [keyId], or `null`
     * when absent or expired (expired entries are cleared).
     */
    fun get(keyId: Long): CharArray? {
        val now = System.currentTimeMillis()
        val entry = entries[keyId] ?: return null
        if (entry.expiresAtMs <= now) {
            clear(keyId)
            return null
        }
        return entry.passphrase.copyOf()
    }

    /** Stores a copy of [passphrase] for [keyId] with a fresh TTL, then trims. */
    fun put(keyId: Long, passphrase: CharArray) {
        clear(keyId)
        entries[keyId] = Entry(passphrase.copyOf(), System.currentTimeMillis() + ttlMs)
        trimToCapacity()
    }

    private fun trimToCapacity() {
        while (entries.size > maxEntries) {
            val oldestKey = entries.minByOrNull { it.value.expiresAtMs }?.key ?: break
            clear(oldestKey)
        }
    }

    /** Removes and zeroes the cached passphrase for [keyId]. */
    fun clear(keyId: Long) {
        entries.remove(keyId)?.passphrase?.fill('\u0000')
    }

    /** Removes and zeroes all cached passphrases (e.g. on screen off/low memory). */
    fun clearAll() {
        entries.keys.toList().forEach(::clear)
    }
}
