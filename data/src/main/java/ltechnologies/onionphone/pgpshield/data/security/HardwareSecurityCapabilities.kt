package ltechnologies.onionphone.pgpshield.data.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.Os
import androidx.biometric.BiometricManager
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory

/**
 * Snapshot of Android hardware / platform security features available to PGP Shield.
 *
 * Includes StrongBox/TEE Keystore, biometric Class-3, ARM MTE, GWP-ASan, and TBI.
 */
data class HardwareSecurityReport(
    val strongBoxKeystore: Boolean,
    val hardwareKeystore: Boolean,
    val deviceSecure: Boolean,
    val biometricStrongAvailable: Boolean,
    val vaultKeyStrongBox: Boolean?,
    val vaultKeyHardwareBacked: Boolean?,
    val vaultKeyAlias: String,
    /** Manifest-requested MTE mode: async / sync / off / unknown. */
    val memtagRequested: String,
    /** Runtime MTE mode from prctl, or off / unsupported. */
    val memtagRuntime: String,
    val gwpAsanRequested: Boolean,
    val nativeHeapPointerTagging: Boolean,
    val summary: String,
)

/** Probes StrongBox, TEE, MTE, GWP-ASan, biometric Class-3, and vault key backing. */
object HardwareSecurityCapabilities {

    /** linux/prctl.h — PR_GET_TAGGED_ADDR_CTRL */
    private const val PR_GET_TAGGED_ADDR_CTRL = 56
    private const val PR_TAGGED_ADDR_ENABLE = 1 shl 0
    private const val PR_MTE_TCF_SYNC = 1 shl 1
    private const val PR_MTE_TCF_ASYNC = 2 shl 1
    private const val PR_MTE_TCF_MASK = PR_MTE_TCF_SYNC or PR_MTE_TCF_ASYNC

    fun report(context: Context, vaultKeyAlias: String = VaultMasterKeyFactory.ALIAS_V2): HardwareSecurityReport {
        val pm = context.packageManager
        val strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        val hardwareKs = pm.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE) ||
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.M
        val keyguard = context.getSystemService(android.app.KeyguardManager::class.java)
        val deviceSecure = keyguard?.isDeviceSecure == true
        val biometric = BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        ) == BiometricManager.BIOMETRIC_SUCCESS

        val (isStrongBox, isHardware) = inspectKey(vaultKeyAlias)
        val appInfo = runCatching {
            pm.getApplicationInfo(context.packageName, 0)
        }.getOrNull()
        val memtagRequested = readMemtagRequested(appInfo)
        val memtagRuntime = readMemtagRuntime()
        val gwpAsan = readGwpAsanAlways(appInfo)
        // Manifest sets allowNativeHeapPointerTagging=true (Android 11+ TBI prep for MTE).
        val pointerTagging = Build.VERSION.SDK_INT >= Build.VERSION_CODES.R

        val summary = buildString {
            append(if (strongBox) "StrongBox" else "No StrongBox")
            append(" · ")
            append(if (hardwareKs) "TEE Keystore" else "soft Keystore")
            append(" · MTE req=")
            append(memtagRequested)
            append(" rt=")
            append(memtagRuntime)
            append(if (gwpAsan) " · GWP-ASan" else "")
            append(if (pointerTagging) " · TBI" else "")
            append(" · vault=")
            when {
                isStrongBox == true -> append("StrongBox")
                isHardware == true -> append("TEE")
                isHardware == false -> append("software")
                else -> append("pending")
            }
        }
        return HardwareSecurityReport(
            strongBoxKeystore = strongBox,
            hardwareKeystore = hardwareKs,
            deviceSecure = deviceSecure,
            biometricStrongAvailable = biometric,
            vaultKeyStrongBox = isStrongBox,
            vaultKeyHardwareBacked = isHardware,
            vaultKeyAlias = vaultKeyAlias,
            memtagRequested = memtagRequested,
            memtagRuntime = memtagRuntime,
            gwpAsanRequested = gwpAsan,
            nativeHeapPointerTagging = pointerTagging,
            summary = summary,
        )
    }

    /**
     * Reads runtime MTE / tagged-address control via prctl.
     * Returns sync / async / sync+async / tagged-ptrs / off / unsupported.
     */
    fun readMemtagRuntime(): String {
        return try {
            val mode = Os.prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0)
            val sync = mode and PR_MTE_TCF_SYNC != 0
            val async = mode and PR_MTE_TCF_ASYNC != 0
            when {
                sync && async -> "sync+async"
                sync -> "sync"
                async -> "async"
                mode and PR_TAGGED_ADDR_ENABLE != 0 -> "tagged-ptrs"
                else -> "off"
            }
        } catch (_: Exception) {
            "unsupported"
        }
    }

    private fun readMemtagRequested(info: ApplicationInfo?): String {
        if (info == null) return "unknown"
        return try {
            // Hidden field ApplicationInfo.memtagMode (API 31+): 0=default,1=off,2=async,3=sync
            val field = ApplicationInfo::class.java.getDeclaredField("memtagMode")
            field.isAccessible = true
            when (field.getInt(info)) {
                0 -> "default"
                1 -> "off"
                2 -> "async"
                3 -> "sync"
                else -> "unknown"
            }
        } catch (_: Exception) {
            // Manifest always sets async (release) / sync (debug) — report request intent.
            "async"
        }
    }

    private fun readGwpAsanAlways(info: ApplicationInfo?): Boolean {
        if (info == null) return true
        return try {
            val field = ApplicationInfo::class.java.getDeclaredField("gwpAsanMode")
            field.isAccessible = true
            // 0=default, 1=never, 2=always
            field.getInt(info) == 2
        } catch (_: Exception) {
            true
        }
    }

    private fun inspectKey(alias: String): Pair<Boolean?, Boolean?> {
        return try {
            val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val key = ks.getKey(alias, null) as? SecretKey ?: return null to null
            val factory = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            val isStrongBox = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
            } else {
                null
            }
            @Suppress("DEPRECATION")
            isStrongBox to info.isInsideSecureHardware
        } catch (_: Exception) {
            null to null
        }
    }
}
