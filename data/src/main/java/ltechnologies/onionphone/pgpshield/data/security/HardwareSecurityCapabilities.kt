package ltechnologies.onionphone.pgpshield.data.security

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.Os
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricManager
import java.security.KeyStore
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import ltechnologies.onionphone.pgpshield.data.SmimeCertificateStore

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
    /** Auth-bound passphrase wrapping key (StrongBox preferred). */
    val passphraseKeyStrongBox: Boolean? = null,
    val passphraseKeyHardwareBacked: Boolean? = null,
    /** S/MIME private-key sealing key (StrongBox preferred, no per-op auth). */
    val smimeKeyStrongBox: Boolean? = null,
    val smimeKeyHardwareBacked: Boolean? = null,
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

    fun report(context: Context, vaultKeyAlias: String = VaultMasterKeyFactory.ALIAS_V2): HardwareSecurityReport {
        val pm = context.packageManager
        val strongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        // FEATURE_HARDWARE_KEYSTORE is API 31+; Keystore itself exists since minSdk.
        val hardwareKs = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            pm.hasSystemFeature(PackageManager.FEATURE_HARDWARE_KEYSTORE)
        } else {
            true
        }
        val keyguard = context.getSystemService(android.app.KeyguardManager::class.java)
        val deviceSecure = keyguard?.isDeviceSecure == true
        val biometric = BiometricManager.from(context).canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL,
        ) == BiometricManager.BIOMETRIC_SUCCESS

        val (isStrongBox, isHardware) = inspectKey(vaultKeyAlias)
        val (passStrongBox, passHardware) = inspectKey(HardwarePassphraseVault.ALIAS)
        val (smimeStrongBox, smimeHardware) = inspectKey(SmimeCertificateStore.SMIME_KEY_ALIAS)
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
            append(" · hw-pass=")
            when {
                passStrongBox == true -> append("StrongBox")
                passHardware == true -> append("TEE+auth")
                passHardware == false -> append("software")
                else -> append("pending")
            }
            append(" · smime=")
            when {
                smimeStrongBox == true -> append("StrongBox")
                smimeHardware == true -> append("TEE")
                smimeHardware == false -> append("software")
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
            passphraseKeyStrongBox = passStrongBox,
            passphraseKeyHardwareBacked = passHardware,
            smimeKeyStrongBox = smimeStrongBox,
            smimeKeyHardwareBacked = smimeHardware,
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
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return "unsupported"
        return memtagModeLabel(info)
    }

    @RequiresApi(Build.VERSION_CODES.S)
    private fun memtagModeLabel(info: ApplicationInfo): String =
        when (info.memtagMode) {
            ApplicationInfo.MEMTAG_DEFAULT -> "default"
            ApplicationInfo.MEMTAG_OFF -> "off"
            ApplicationInfo.MEMTAG_ASYNC -> "async"
            ApplicationInfo.MEMTAG_SYNC -> "sync"
            else -> "unknown"
        }

    private fun readGwpAsanAlways(info: ApplicationInfo?): Boolean {
        if (info == null) return true
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) return true
        return gwpAsanIsAlways(info)
    }

    @RequiresApi(Build.VERSION_CODES.R)
    private fun gwpAsanIsAlways(info: ApplicationInfo): Boolean =
        info.gwpAsanMode == ApplicationInfo.GWP_ASAN_ALWAYS

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
