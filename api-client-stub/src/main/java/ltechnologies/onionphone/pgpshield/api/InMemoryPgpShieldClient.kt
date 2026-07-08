package ltechnologies.onionphone.pgpshield.api

import ltechnologies.onionphone.pgpshield.api.PermissionState.GRANTED

/**
 * In-memory [PgpShieldClient] for unit tests and local development without the AIDL service.
 *
 * Returns passthrough crypto results (output equals input) and a fixed test key list.
 * Permission is granted when the internal [granted] flag is true.
 */
class InMemoryPgpShieldClient : PgpShieldClient {
    private var granted = true
    private val keys = mutableListOf(
        KeySummaryParcel(1L, "AA BB", "Test <t@e.com>", true),
    )
    private val caller = CallerIdentity("dev.test", 0)

    /** @see PgpShieldClient.checkPermission */
    override suspend fun checkPermission(caller: CallerIdentity): PermissionState =
        if (granted) GRANTED else PermissionState.DENIED

    /** @see PgpShieldClient.encrypt — returns plaintext unchanged as output. */
    override suspend fun encrypt(request: EncryptRequestParcel): CryptoResultParcel =
        CryptoResultParcel(true, output = request.plaintext)

    /** @see PgpShieldClient.decrypt — returns ciphertext unchanged as output. */
    override suspend fun decrypt(request: DecryptRequestParcel): CryptoResultParcel =
        CryptoResultParcel(true, output = request.ciphertext)

    /** @see PgpShieldClient.sign — returns input data unchanged as output. */
    override suspend fun sign(request: SignRequestParcel): CryptoResultParcel =
        CryptoResultParcel(true, output = request.data)

    /** @see PgpShieldClient.listKeys — returns the fixed in-memory key list. */
    override suspend fun listKeys(packageName: String): List<KeySummaryParcel> = keys
}
