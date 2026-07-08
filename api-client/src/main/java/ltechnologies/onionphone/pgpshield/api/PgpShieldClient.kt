package ltechnologies.onionphone.pgpshield.api

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Kotlin-facing client API for the PGP Shield bound IPC crypto service.
 *
 * Implementations may use AIDL ([PgpShieldClientImpl]) or in-memory stubs for tests.
 */

/**
 * Suspend API for encrypt, decrypt, sign, and key listing on behalf of a calling app.
 */
interface PgpShieldClient {
    /** Checks whether [caller] may use crypto APIs and whether user consent is required. */
    suspend fun checkPermission(caller: CallerIdentity): PermissionState

    /** Encrypts plaintext for the given recipient key ids. */
    suspend fun encrypt(request: EncryptRequestParcel): CryptoResultParcel

    /** Decrypts ciphertext with the specified decrypt key and optional passphrase. */
    suspend fun decrypt(request: DecryptRequestParcel): CryptoResultParcel

    /** Signs data with the specified signing key and optional passphrase. */
    suspend fun sign(request: SignRequestParcel): CryptoResultParcel

    /** Lists key summaries visible to [packageName] per API grant policy. */
    suspend fun listKeys(packageName: String): List<KeySummaryParcel>
}

/**
 * AIDL-backed [PgpShieldClient] that binds to [SERVICE_ACTION] in the host app package.
 *
 * Call [connect] once before other methods; the connection is torn down on coroutine cancellation.
 */
class PgpShieldClientImpl(
    private val context: Context,
) : PgpShieldClient {
    private var binder: IPgpShieldService? = null

    /**
     * Binds to the PGP Shield service and waits until the AIDL stub is ready.
     *
     * @throws Exception if binding fails or is cancelled before connect completes.
     */
    suspend fun connect(): Unit = suspendCancellableCoroutine { cont ->
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                binder = IPgpShieldService.Stub.asInterface(service)
                cont.resume(Unit)
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                binder = null
            }
        }
        val intent = Intent(SERVICE_ACTION).setPackage(context.packageName)
        context.bindService(intent, connection, Context.BIND_AUTO_CREATE)
        cont.invokeOnCancellation { context.unbindService(connection) }
    }

    private fun service(): IPgpShieldService =
        binder ?: error("Not connected — call connect() first")

    /** @see PgpShieldClient.checkPermission */
    override suspend fun checkPermission(caller: CallerIdentity): PermissionState =
        when (service().checkPermission(caller)) {
            0 -> PermissionState.GRANTED
            1 -> PermissionState.REQUIRES_USER_CONSENT
            else -> PermissionState.DENIED
        }

    /** @see PgpShieldClient.encrypt */
    override suspend fun encrypt(request: EncryptRequestParcel): CryptoResultParcel =
        service().encrypt(request)

    /** @see PgpShieldClient.decrypt */
    override suspend fun decrypt(request: DecryptRequestParcel): CryptoResultParcel =
        service().decrypt(request)

    /** @see PgpShieldClient.sign */
    override suspend fun sign(request: SignRequestParcel): CryptoResultParcel =
        service().sign(request)

    /** @see PgpShieldClient.listKeys */
    override suspend fun listKeys(packageName: String): List<KeySummaryParcel> =
        service().listKeys(packageName)

    companion object {
        /** Intent action for binding to the PGP Shield AIDL service. */
        const val SERVICE_ACTION = "ltechnologies.onionphone.pgpshield.api.PgpShieldService"
    }
}
