package ltechnologies.onionphone.pgpshield.engine

/**
 * Abstraction for OpenPGP smart-card and hardware token operations.
 *
 * Implementations can delegate signing and decryption to a connected smart card
 * instead of software secret keys.
 */

/** Port for hardware-backed signing and session-key decryption. */
interface SmartCardPort {
    /** Returns `true` when a smart card is connected and ready. */
    fun isAvailable(): Boolean = false

    /** Signs [data] with the private key identified by [keyId]. */
    fun sign(data: ByteArray, keyId: Long): ByteArray =
        throw UnsupportedOperationException("Smart card signing not implemented")

    /** Decrypts an encrypted session key using the smart-card private key [keyId]. */
    fun decrypt(sessionKey: ByteArray, keyId: Long): ByteArray =
        throw UnsupportedOperationException("Smart card decryption not implemented")
}
