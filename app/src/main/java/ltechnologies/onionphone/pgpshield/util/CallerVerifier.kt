package ltechnologies.onionphone.pgpshield.util

/**
 * Verifies that an IPC caller actually owns the package name it claims.
 *
 * These checks defend against spoofing on the OpenPGP API boundary by cross
 * referencing the claimed identity against the kernel-provided calling UID.
 */

import android.content.Context
import android.os.Binder
import ltechnologies.onionphone.pgpshield.api.CallerIdentity

/** Validates the authenticity of binder/intent callers before granting access. */
object CallerVerifier {
    /**
     * Confirms that [caller] matches the current binder UID and returns the
     * verified package name.
     *
     * @throws IllegalArgumentException if the package or UID does not belong to
     *   the calling process.
     */
    fun verifiedPackage(context: Context, caller: CallerIdentity): String {
        val uid = Binder.getCallingUid()
        @Suppress("DEPRECATION")
        val packages = context.packageManager.getPackagesForUid(uid) ?: emptyArray()
        require(caller.packageName in packages) { "Caller identity mismatch" }
        require(caller.uid == uid || caller.uid == 0) { "Caller UID mismatch" }
        return caller.packageName
    }

    /**
     * Confirms that [packageName] is owned by the calling UID and returns it.
     *
     * @throws IllegalArgumentException if the package is not owned by the caller.
     */
    fun verifiedPackageFromIntent(context: Context, packageName: String): String {
        val uid = Binder.getCallingUid()
        @Suppress("DEPRECATION")
        val packages = context.packageManager.getPackagesForUid(uid) ?: emptyArray()
        require(packageName in packages) { "Package not owned by caller" }
        return packageName
    }
}
