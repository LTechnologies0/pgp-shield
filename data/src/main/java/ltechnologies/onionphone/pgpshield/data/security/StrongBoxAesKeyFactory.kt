package ltechnologies.onionphone.pgpshield.data.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import timber.log.Timber
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Creates AES-256-GCM AndroidKeyStore keys, preferring StrongBox then TEE.
 *
 * Soft Keystore keys are rejected when [requireInsideSecureHardware] is true.
 */
object StrongBoxAesKeyFactory {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val TRANSFORMATION_HINT = "AES/GCM/NoPadding"

    data class KeyHandle(
        val key: SecretKey,
        val alias: String,
        val strongBoxBacked: Boolean?,
        val insideSecureHardware: Boolean,
        val userAuthenticationRequired: Boolean,
    )

    /** True when the device advertises StrongBox Keystore (API 28+). */
    fun isStrongBoxFeaturePresent(context: Context): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /**
     * Loads [alias] or creates it. Tries StrongBox first when available.
     *
     * @param userAuthenticationRequired When true, every Cipher use needs BiometricPrompt CryptoObject.
     * @param requireInsideSecureHardware Fail if the resulting key is not in TEE/StrongBox.
     */
    fun getOrCreate(
        context: Context,
        alias: String,
        userAuthenticationRequired: Boolean = false,
        requireInsideSecureHardware: Boolean = true,
    ): KeyHandle {
        load(alias)?.let { existing ->
            val handle = inspect(existing, alias)
            if (requireInsideSecureHardware) {
                require(handle.insideSecureHardware) {
                    "Keystore key $alias is not inside secure hardware"
                }
            }
            return handle
        }

        val wantStrongBox = isStrongBoxFeaturePresent(context)
        if (wantStrongBox) {
            try {
                generate(
                    alias = alias,
                    requestStrongBox = true,
                    userAuthenticationRequired = userAuthenticationRequired,
                )
                val handle = inspect(load(alias)!!, alias)
                if (requireInsideSecureHardware) {
                    require(handle.insideSecureHardware) {
                        "StrongBox key $alias not inside secure hardware"
                    }
                }
                Timber.i(
                    "Created Keystore AES key alias=%s strongBox=%s hardware=%s auth=%s",
                    alias,
                    handle.strongBoxBacked,
                    handle.insideSecureHardware,
                    handle.userAuthenticationRequired,
                )
                return handle
            } catch (e: StrongBoxUnavailableException) {
                Timber.w(e, "StrongBox unavailable for %s — TEE fallback", alias)
            } catch (e: Exception) {
                Timber.w(e, "StrongBox key gen failed for %s — TEE fallback", alias)
                // Delete partial alias if any.
                runCatching { delete(alias) }
            }
        }

        generate(
            alias = alias,
            requestStrongBox = false,
            userAuthenticationRequired = userAuthenticationRequired,
        )
        val handle = inspect(load(alias)!!, alias)
        if (requireInsideSecureHardware) {
            require(handle.insideSecureHardware) {
                "Refusing software Keystore for $alias — secure hardware required"
            }
        }
        Timber.i(
            "Created Keystore AES key alias=%s strongBox=%s hardware=%s auth=%s",
            alias,
            handle.strongBoxBacked,
            handle.insideSecureHardware,
            handle.userAuthenticationRequired,
        )
        return handle
    }

    fun inspect(alias: String): KeyHandle? = load(alias)?.let { inspect(it, alias) }

    fun delete(alias: String) {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    /** AES/GCM transform used with keys from this factory. */
    fun transformation(): String = TRANSFORMATION_HINT

    private fun load(alias: String): SecretKey? {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.getKey(alias, null) as? SecretKey
    }

    private fun generate(
        alias: String,
        requestStrongBox: Boolean,
        userAuthenticationRequired: Boolean,
    ) {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(userAuthenticationRequired)

        if (userAuthenticationRequired) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(
                    0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(0)
            }
        }

        if (requestStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }

        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }

    private fun inspect(key: SecretKey, alias: String): KeyHandle {
        val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
        val strongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            null
        }
        @Suppress("DEPRECATION")
        val hardware = info.isInsideSecureHardware
        return KeyHandle(
            key = key,
            alias = alias,
            strongBoxBacked = strongBox,
            insideSecureHardware = hardware,
            userAuthenticationRequired = info.isUserAuthenticationRequired,
        )
    }
}
