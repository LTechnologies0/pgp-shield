package ltechnologies.onionphone.pgpshield.data

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.io.File
import java.security.GeneralSecurityException
import javax.crypto.AEADBadTagException
import ltechnologies.onionphone.pgpshield.data.security.VaultMasterKeyFactory
import timber.log.Timber

/**
 * Factory for AES-encrypted [SharedPreferences] backed by Android Keystore (StrongBox-preferred).
 *
 * EncryptedSharedPreferences stores Tink keysets **inside** the named prefs file, so each
 * [name] is already isolated. A MasterKey alias change on an existing file still yields
 * [AEADBadTagException] — callers that need recovery should catch and recreate.
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

    /**
     * Opens [name], or wipes and recreates it if the MasterKey can no longer decrypt the
     * embedded Tink keysets (Keystore wipe / alias mismatch).
     *
     * @return prefs plus whether a destructive reset occurred.
     */
    fun createOrReset(context: Context, name: String): Pair<SharedPreferences, Boolean> {
        return try {
            create(context, name) to false
        } catch (e: Exception) {
            if (!isKeysetCorruption(e)) throw e
            Timber.e(e, "Encrypted prefs %s unreadable — resetting", name)
            deletePrefsFiles(context, name)
            create(context, name) to true
        }
    }

    private fun isKeysetCorruption(e: Throwable): Boolean {
        var cur: Throwable? = e
        while (cur != null) {
            if (cur is AEADBadTagException) return true
            val msg = cur.message.orEmpty()
            if (cur is GeneralSecurityException &&
                (msg.contains("tag", ignoreCase = true) ||
                    msg.contains("decrypt", ignoreCase = true) ||
                    msg.contains("MAC", ignoreCase = true))
            ) {
                return true
            }
            cur = cur.cause
        }
        return false
    }

    private fun deletePrefsFiles(context: Context, name: String) {
        // Synchronous wipe required before recreating EncryptedSharedPreferences keysets.
        @Suppress("ApplySharedPref")
        context.getSharedPreferences(name, Context.MODE_PRIVATE).edit().clear().commit()
        val dir = File(context.applicationInfo.dataDir, "shared_prefs")
        File(dir, "$name.xml").delete()
        File(dir, "$name.xml.bak").delete()
    }
}
