package ltechnologies.onionphone.pgpshield.data

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Persists OpenKeychain-style insecure-crypto warning overrides.
 *
 * Mail clients (K-9 / FairEmail) read OpenPGP API `RESULT_OVERRIDE_CRYPTO_WARNING`
 * after the user confirms the insecure-crypto detail activity; subsequent decrypts must
 * report `true` for the same problem id so the client stops blocking display.
 */
@Singleton
class CryptoWarningOverrideStore @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun isOverridden(problemId: String): Boolean {
        if (problemId.isBlank()) return false
        return prefs.getBoolean(key(problemId), false)
    }

    fun setOverridden(problemId: String) {
        if (problemId.isBlank()) return
        prefs.edit().putBoolean(key(problemId), true).apply()
    }

    private fun key(problemId: String): String = "override_$problemId"

    companion object {
        private const val PREFS_NAME = "crypto_warning_overrides"
    }
}
