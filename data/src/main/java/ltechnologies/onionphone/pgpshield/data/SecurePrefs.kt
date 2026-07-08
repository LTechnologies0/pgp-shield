package ltechnologies.onionphone.pgpshield.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Factory for AES-encrypted [SharedPreferences] backed by Android Keystore.
 *
 * Centralizes master-key creation and encryption scheme selection so callers receive
 * preferences whose keys and values are encrypted at rest.
 */
object SecurePrefs {
    private const val KEY_ALIAS = "__pgp_shield_secure_prefs__"

    /**
     * Creates or opens an encrypted preferences file with the given [name].
     *
     * @param context Application context used for keystore and file access.
     * @param name Preferences file name (stored under the app's private data directory).
     * @return [SharedPreferences] instance with AES-256-SIV key encryption and AES-256-GCM
     *   value encryption.
     */
    fun create(context: Context, name: String): SharedPreferences {
        val masterKey = MasterKey.Builder(context, KEY_ALIAS)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        return EncryptedSharedPreferences.create(
            context,
            name,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }
}
