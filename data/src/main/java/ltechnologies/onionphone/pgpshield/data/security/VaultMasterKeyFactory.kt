package ltechnologies.onionphone.pgpshield.data.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.StrongBoxUnavailableException
import androidx.security.crypto.MasterKey
import timber.log.Timber
import java.security.GeneralSecurityException

/**
 * Builds Jetpack Security [MasterKey]s preferring StrongBox, falling back to TEE Keystore.
 *
 * User-authentication is **not** bound on the EncryptedFile master key (Jetpack opens
 * ciphers internally without BiometricPrompt CryptoObject). App lock + device FBE gate access.
 */
object VaultMasterKeyFactory {
    /** Legacy default alias used by earlier pgp-shield builds. */
    const val ALIAS_LEGACY = MasterKey.DEFAULT_MASTER_KEY_ALIAS

    /** StrongBox-preferred vault alias (AES-256-GCM). */
    const val ALIAS_V2 = "_pgp_shield_vault_v2_"

    /** Settings / SecurePrefs alias. */
    const val ALIAS_PREFS = "_pgp_shield_secure_prefs_v2_"

    fun createVaultKey(context: Context): MasterKey =
        create(context, ALIAS_V2, requestStrongBox = true)

    fun createLegacyVaultKey(context: Context): MasterKey =
        create(context, ALIAS_LEGACY, requestStrongBox = false)

    fun createPrefsKey(context: Context): MasterKey =
        create(context, ALIAS_PREFS, requestStrongBox = true)

    private fun create(context: Context, alias: String, requestStrongBox: Boolean): MasterKey {
        val wantStrongBox = requestStrongBox &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

        if (wantStrongBox) {
            try {
                return MasterKey.Builder(context, alias)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .setRequestStrongBoxBacked(true)
                    .build()
            } catch (e: StrongBoxUnavailableException) {
                Timber.w(e, "StrongBox unavailable for %s — falling back to TEE Keystore", alias)
            } catch (e: GeneralSecurityException) {
                Timber.w(e, "StrongBox MasterKey failed for %s — falling back to TEE", alias)
            } catch (e: Exception) {
                Timber.w(e, "StrongBox MasterKey failed for %s — falling back to TEE", alias)
            }
        }

        return MasterKey.Builder(context, alias)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .setRequestStrongBoxBacked(false)
            .build()
    }
}
