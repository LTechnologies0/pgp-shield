package org.openintents.openpgp

/**
 * Parcelable plaintext metadata for the OpenPGP API IPC contract.
 *
 * Wire-compatible with openpgp-api [org.openintents.openpgp.OpenPgpMetadata]
 * so clients can unmarshal `RESULT_METADATA` extras.
 */

import android.os.Parcel
import android.os.Parcelable

/**
 * @property filename Literal-data filename, or a console placeholder.
 * @property mimeType Optional MIME type.
 * @property modificationTime Optional modification time (ms since epoch); `0` if unknown.
 * @property originalSize Plaintext size in bytes.
 * @property charset Optional charset from ASCII-armor headers.
 */
class OpenPgpMetadata(
    var filename: String? = null,
    var mimeType: String? = null,
    var modificationTime: Long = 0L,
    var originalSize: Long = 0L,
    var charset: String? = null,
) : Parcelable {

    constructor(
        filename: String?,
        mimeType: String?,
        modificationTime: Long,
        originalSize: Long,
    ) : this(filename, mimeType, modificationTime, originalSize, charset = null)

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(PARCELABLE_VERSION)
        val sizePosition = dest.dataPosition()
        dest.writeInt(0)
        val startPosition = dest.dataPosition()
        dest.writeString(filename)
        dest.writeString(mimeType)
        dest.writeLong(modificationTime)
        dest.writeLong(originalSize)
        dest.writeString(charset)
        val parcelableSize = dest.dataPosition() - startPosition
        dest.setDataPosition(sizePosition)
        dest.writeInt(parcelableSize)
        dest.setDataPosition(startPosition + parcelableSize)
    }

    companion object {
        const val PARCELABLE_VERSION = 2

        @JvmField
        val CREATOR = object : Parcelable.Creator<OpenPgpMetadata> {
            override fun createFromParcel(source: Parcel): OpenPgpMetadata {
                val version = source.readInt()
                val parcelableSize = source.readInt()
                val startPosition = source.dataPosition()
                val meta = OpenPgpMetadata(
                    filename = source.readString(),
                    mimeType = source.readString(),
                    modificationTime = source.readLong(),
                    originalSize = source.readLong(),
                    charset = if (version >= 2) source.readString() else null,
                )
                source.setDataPosition(startPosition + parcelableSize)
                return meta
            }

            override fun newArray(size: Int): Array<OpenPgpMetadata?> = arrayOfNulls(size)
        }
    }
}
