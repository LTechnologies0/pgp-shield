package org.openintents.openpgp

/**
 * Parcelable decryption-status result for the OpenPGP API IPC contract.
 *
 * Wire-compatible with openpgp-api [org.openintents.openpgp.OpenPgpDecryptionResult]
 * so clients can unmarshal `RESULT_DECRYPTION` extras.
 */

import android.os.Parcel
import android.os.Parcelable

/**
 * @property result One of [RESULT_NOT_ENCRYPTED], [RESULT_INSECURE], or [RESULT_ENCRYPTED].
 */
class OpenPgpDecryptionResult(
    private val result: Int,
    private val sessionKey: ByteArray? = null,
    private val decryptedSessionKey: ByteArray? = null,
) : Parcelable {

    init {
        require((sessionKey == null) == (decryptedSessionKey == null)) {
            "sessionKey must be null iff decryptedSessionKey is null"
        }
    }

    fun getResult(): Int = result

    fun hasDecryptedSessionKey(): Boolean = sessionKey != null && decryptedSessionKey != null

    fun getSessionKey(): ByteArray? = sessionKey?.copyOf()

    fun getDecryptedSessionKey(): ByteArray? = decryptedSessionKey?.copyOf()

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(PARCELABLE_VERSION)
        val sizePosition = dest.dataPosition()
        dest.writeInt(0)
        val startPosition = dest.dataPosition()
        dest.writeInt(result)
        dest.writeByteArray(sessionKey)
        dest.writeByteArray(decryptedSessionKey)
        val parcelableSize = dest.dataPosition() - startPosition
        dest.setDataPosition(sizePosition)
        dest.writeInt(parcelableSize)
        dest.setDataPosition(startPosition + parcelableSize)
    }

    companion object {
        const val PARCELABLE_VERSION = 2

        const val RESULT_NOT_ENCRYPTED = -1
        const val RESULT_INSECURE = 0
        const val RESULT_ENCRYPTED = 1

        @JvmField
        val CREATOR = object : Parcelable.Creator<OpenPgpDecryptionResult> {
            override fun createFromParcel(source: Parcel): OpenPgpDecryptionResult {
                val version = source.readInt()
                val parcelableSize = source.readInt()
                val startPosition = source.dataPosition()
                val result = source.readInt()
                val sessionKey = if (version > 1) source.createByteArray() else null
                val decryptedSessionKey = if (version > 1) source.createByteArray() else null
                source.setDataPosition(startPosition + parcelableSize)
                return OpenPgpDecryptionResult(result, sessionKey, decryptedSessionKey)
            }

            override fun newArray(size: Int): Array<OpenPgpDecryptionResult?> = arrayOfNulls(size)
        }
    }
}
