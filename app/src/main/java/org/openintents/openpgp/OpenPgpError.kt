package org.openintents.openpgp

/**
 * Parcelable error payload for the OpenPGP API IPC contract.
 *
 * This type mirrors the historical `openpgp-api` library so that third-party
 * clients can unmarshal error extras returned by the service without changes.
 */

import android.os.Parcel
import android.os.Parcelable

/**
 * Wire-compatible with openpgp-api [org.openintents.openpgp.OpenPgpError] for IPC result extras.
 *
 * @property errorId One of the `*_ERROR` constants describing the failure kind.
 * @property message Optional human-readable description of the failure.
 */
class OpenPgpError(
    var errorId: Int = GENERIC_ERROR,
    var message: String? = null,
) : Parcelable {

    /** Reconstructs an error from a versioned/size-prefixed [Parcel]. */
    constructor(parcel: Parcel) : this() {
        parcel.readInt() // parcelableVersion
        val parcelableSize = parcel.readInt()
        val startPosition = parcel.dataPosition()
        errorId = parcel.readInt()
        message = parcel.readString()
        parcel.setDataPosition(startPosition + parcelableSize)
    }

    /** Serializes the error using the version/size envelope expected by clients. */
    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(PARCELABLE_VERSION)
        val sizePosition = dest.dataPosition()
        dest.writeInt(0)
        val startPosition = dest.dataPosition()
        dest.writeInt(errorId)
        dest.writeString(message)
        val parcelableSize = dest.dataPosition() - startPosition
        dest.setDataPosition(sizePosition)
        dest.writeInt(parcelableSize)
        dest.setDataPosition(startPosition + parcelableSize)
    }

    override fun describeContents(): Int = 0

    /** Parcel envelope version and stable numeric error codes for the API. */
    companion object {
        const val PARCELABLE_VERSION = 1
        const val CLIENT_SIDE_ERROR = -1
        const val GENERIC_ERROR = 0
        const val INCOMPATIBLE_API_VERSIONS = 1
        const val NO_OR_WRONG_PASSPHRASE = 2
        const val NO_USER_IDS = 3

        @JvmField
        val CREATOR = object : Parcelable.Creator<OpenPgpError> {
            override fun createFromParcel(source: Parcel) = OpenPgpError(source)
            override fun newArray(size: Int) = arrayOfNulls<OpenPgpError>(size)
        }
    }
}
