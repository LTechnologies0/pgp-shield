package ltechnologies.onionphone.pgpshield.data.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.security.crypto.MasterKey
import timber.log.Timber
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Builds Jetpack Security [MasterKey]s preferring StrongBox, falling back to TEE Keystore.
 *
 * User-authentication is **not** bound on the EncryptedFile master key (Jetpack opens
 * ciphers internally without BiometricPrompt CryptoObject). App lock + device FBE gate access.
 * StrongBox is requested for every alias, including legacy, whenever the feature is present.
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
        create(context, ALIAS_LEGACY, requestStrongBox = true)

    fun createPrefsKey(context: Context): MasterKey =
        create(context, ALIAS_PREFS, requestStrongBox = true)

    private fun create(context: Context, alias: String, requestStrongBox: Boolean): MasterKey {
        val wantStrongBox = requestStrongBox &&
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

        if (wantStrongBox) {
            try {
                val key = MasterKey.Builder(context, alias)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .setRequestStrongBoxBacked(true)
                    .build()
                logBacking(alias, preferStrongBox = true)
                return key
            } catch (e: StrongBoxUnavailableException) {
                Timber.w(e, "StrongBox unavailable for %s — falling back to TEE Keystore", alias)
            } catch (e: GeneralSecurityException) {
                Timber.w(e, "StrongBox MasterKey failed for %s — falling back to TEE", alias)
            } catch (e: Exception) {
                Timber.w(e, "StrongBox MasterKey failed for %s — falling back to TEE", alias)
            }
        }

        val key = MasterKey.Builder(context, alias)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .setRequestStrongBoxBacked(false)
            .build()
        logBacking(alias, preferStrongBox = false)
        return key
    }

    private fun logBacking(alias: String, preferStrongBox: Boolean) {
        try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val secret = ks.getKey(alias, null) as? SecretKey ?: return
            val factory = SecretKeyFactory.getInstance(secret.algorithm, "AndroidKeyStore")
            val info = factory.getKeySpec(secret, KeyInfo::class.java) as KeyInfo
            val strongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } else {
                null
            }
            @Suppress("DEPRECATION")
            Timber.i(
                "MasterKey alias=%s preferStrongBox=%s strongBox=%s hardware=%s",
                alias,
                preferStrongBox,
                strongBox,
                info.isInsideSecureHardware,
            )
        } catch (e: Exception) {
            Timber.d(e, "Could not inspect MasterKey backing for %s", alias)
        }
    }
}
