package ltechnologies.onionphone.pgpshield.api

import java.util.concurrent.ConcurrentHashMap
import javax.inject.Inject
import javax.inject.Singleton

/** One-shot confirmation that a caller approved exporting secret key material. */
@Singleton
class ApiBackupConfirmCache @Inject constructor() {
    private val confirmed = ConcurrentHashMap<String, Long>()
    private val ttlMs = 5 * 60 * 1000L

    fun markConfirmed(packageName: String, keyIds: List<Long>) {
        confirmed[key(packageName, keyIds)] = System.currentTimeMillis() + ttlMs
    }

    fun isConfirmed(packageName: String, keyIds: List<Long>): Boolean {
        val stamp = confirmed[key(packageName, keyIds)] ?: return false
        if (stamp <= System.currentTimeMillis()) {
            confirmed.remove(key(packageName, keyIds))
            return false
        }
        return true
    }

    /** Removes a still-valid confirmation so a later backup must prompt again. */
    fun consume(packageName: String, keyIds: List<Long>): Boolean {
        if (!isConfirmed(packageName, keyIds)) return false
        confirmed.remove(key(packageName, keyIds))
        return true
    }

    private fun key(packageName: String, keyIds: List<Long>): String =
        packageName + ":" + keyIds.sorted().joinToString(",")
}
