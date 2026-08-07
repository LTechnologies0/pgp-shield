package ltechnologies.onionphone.pgpshield.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import ltechnologies.onionphone.pgpshield.data.security.VaultMasterKeyFactory

/**
 * Factory for AES-encrypted [SharedPreferences] backed by Android Keystore (StrongBox-preferred).
 */
object SecurePrefs {
    /**
     * Creates or opens an encrypted preferences file with the given [name].
     *
     * Prefers StrongBox via [VaultMasterKeyFactory]; falls back to TEE hardware Keystore.
     */
    fun create(context: Context, name: String): SharedPreferences {
        val masterKey: MasterKey = VaultMasterKeyFactory.createPrefsKey(context)
        return EncryptedSharedPreferences.create(
            context,
            name,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }
}
