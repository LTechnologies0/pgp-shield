package ltechnologies.onionphone.pgpshield.engine

/**
 * Abstraction for OpenPGP smart-card and hardware token operations.
 *
 * Implementations can delegate signing and decryption to a connected smart card
 * instead of software secret keys.
 */

/** Slot identifiers on an OpenPGP Card (ISO 7816). */
enum class OpenPgpCardSlot {
    SIGN,
    DECRYPT,
    AUTH,
}

/** Snapshot of a connected OpenPGP Card. */
data class OpenPgpCardInfo(
    val aid: String,
    val serial: String?,
    val hasSignKey: Boolean,
    val hasDecryptKey: Boolean,
    val hasAuthKey: Boolean,
    val transport: String,
)

/** Port for hardware-backed signing and session-key decryption. */
interface SmartCardPort {
    /** Returns `true` when a smart card is connected and ready. */
    fun isAvailable(): Boolean = false

    /** Latest card info if a session is active. */
    fun cardInfo(): OpenPgpCardInfo? = null

    /** Verify user PIN (PW1). Returns true on success. */
    fun verifyPin(pin: CharArray): Boolean =
        throw UnsupportedOperationException("Smart card PIN verify not implemented")

    /** Signs [data] with the private key identified by [keyId] (or SIGN slot). */
    fun sign(data: ByteArray, keyId: Long): ByteArray =
        throw UnsupportedOperationException("Smart card signing not implemented")

    /** Decrypts an encrypted session key using the smart-card private key [keyId]. */
    fun decrypt(sessionKey: ByteArray, keyId: Long): ByteArray =
        throw UnsupportedOperationException("Smart card decryption not implemented")

    /** True when [keyId] is bound to this card (or card is in divert-to-card mode). */
    fun ownsKey(keyId: Long): Boolean = false

    /** Associates OpenPGP key ids with this card session for [ownsKey] / divert-to-card. */
    fun bindKeyIds(ids: Set<Long>) {}

    /** Release NFC/USB session. */
    fun close() {}
}

/** No-op port used when hardware is absent. */
object NullSmartCardPort : SmartCardPort

/**
 * Tries [delegates] in order; first available wins for [isAvailable]/operations.
 */
class CompositeSmartCardPort(
    private val delegates: List<SmartCardPort>,
) : SmartCardPort {
    private fun active(): SmartCardPort? = delegates.firstOrNull { it.isAvailable() }

    override fun isAvailable(): Boolean = active() != null

    override fun cardInfo(): OpenPgpCardInfo? = active()?.cardInfo()

    override fun verifyPin(pin: CharArray): Boolean =
        active()?.verifyPin(pin) ?: false

    override fun sign(data: ByteArray, keyId: Long): ByteArray =
        active()?.sign(data, keyId)
            ?: throw UnsupportedOperationException("No smart card available")

    override fun decrypt(sessionKey: ByteArray, keyId: Long): ByteArray =
        active()?.decrypt(sessionKey, keyId)
            ?: throw UnsupportedOperationException("No smart card available")

    override fun ownsKey(keyId: Long): Boolean =
        delegates.any { it.ownsKey(keyId) }

    override fun bindKeyIds(ids: Set<Long>) {
        delegates.forEach { it.bindKeyIds(ids) }
    }

    override fun close() {
        delegates.forEach { it.close() }
    }
}
