package ltechnologies.onionphone.pgpshield.util

/**
 * Verifies that an IPC caller actually owns the package name it claims.
 *
 * These checks defend against spoofing on the OpenPGP API boundary by cross
 * referencing the claimed identity against the kernel-provided calling UID.
 */

import android.content.Context
import android.content.pm.PackageManager
import android.os.Binder
import android.os.Process
import ltechnologies.onionphone.pgpshield.api.CallerIdentity

/** Validates the authenticity of binder/intent callers before granting access. */
object CallerVerifier {
    /**
     * Confirms that [caller] matches [callingUid] (captured on the binder thread)
     * and returns the verified package name.
     *
     * @throws IllegalArgumentException if the package or UID does not belong to
     *   the calling process, or if the binder UID collapsed to this process UID
     *   while claiming a third-party package.
     */
    fun verifiedPackage(
        context: Context,
        caller: CallerIdentity,
        callingUid: Int = Binder.getCallingUid(),
    ): String {
        assertCallerUidNotProcess(callingUid, Process.myUid(), caller.packageName, context.packageName)
        @Suppress("DEPRECATION")
        val packages = context.packageManager.getPackagesForUid(callingUid) ?: emptyArray()
        require(caller.packageName in packages) { "Caller identity mismatch" }
        require(caller.uid == callingUid || caller.uid == 0) { "Caller UID mismatch" }
        return caller.packageName
    }

    /**
     * Trusts [packageName] baked into an immutable PendingIntent created by the
     * service (not [Binder.getCallingUid] in an Activity). Confirms the package
     * is installed.
     */
    fun packageFromImmutableGrant(context: Context, packageName: String): String {
        require(packageName.isNotBlank()) { "Missing grant package" }
        try {
            context.packageManager.getPackageInfo(packageName, 0)
        } catch (_: PackageManager.NameNotFoundException) {
            throw IllegalArgumentException("Unknown package")
        }
        return packageName
    }

    /**
     * Rejects a binder identity that collapsed to this process while claiming
     * another package (typical after reading [Binder.getCallingUid] off the
     * binder thread).
     */
    fun assertCallerUidNotProcess(
        callingUid: Int,
        processUid: Int,
        claimedPackage: String,
        ownPackage: String,
    ) {
        require(callingUid != processUid || claimedPackage == ownPackage) {
            "Caller UID collapsed to process UID"
        }
    }
}
