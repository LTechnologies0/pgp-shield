package org.openintents.openpgp

/**
 * Parcelable Autocrypt peer update for the OpenPGP API IPC contract.
 *
 * Wire-compatible with openpgp-api [org.openintents.openpgp.AutocryptPeerUpdate].
 */

import android.os.Parcel
import android.os.Parcelable
import java.util.Date

class AutocryptPeerUpdate private constructor(
    private val keyData: ByteArray?,
    private val effectiveDate: Date?,
    private val preferEncrypt: PreferEncrypt,
) : Parcelable {

    fun getKeyData(): ByteArray? = keyData

    fun hasKeyData(): Boolean = keyData != null

    fun getEffectiveDate(): Date? = effectiveDate

    fun getPreferEncrypt(): PreferEncrypt = preferEncrypt

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(PARCELABLE_VERSION)
        val sizePosition = dest.dataPosition()
        dest.writeInt(0)
        val startPosition = dest.dataPosition()
        dest.writeByteArray(keyData)
        if (effectiveDate != null) {
            dest.writeInt(1)
            dest.writeLong(effectiveDate.time)
        } else {
            dest.writeInt(0)
        }
        dest.writeInt(preferEncrypt.ordinal)
        val parcelableSize = dest.dataPosition() - startPosition
        dest.setDataPosition(sizePosition)
        dest.writeInt(parcelableSize)
        dest.setDataPosition(startPosition + parcelableSize)
    }

    enum class PreferEncrypt {
        NOPREFERENCE,
        MUTUAL,
    }

    companion object {
        const val PARCELABLE_VERSION = 1

        @JvmStatic
        fun createAutocryptPeerUpdate(keyData: ByteArray?, timestamp: Date?): AutocryptPeerUpdate =
            AutocryptPeerUpdate(keyData, timestamp, PreferEncrypt.NOPREFERENCE)

        @JvmField
        val CREATOR = object : Parcelable.Creator<AutocryptPeerUpdate> {
            override fun createFromParcel(source: Parcel): AutocryptPeerUpdate {
                source.readInt() // version
                val parcelableSize = source.readInt()
                val startPosition = source.dataPosition()
                val keyData = source.createByteArray()
                val effectiveDate = if (source.readInt() != 0) Date(source.readLong()) else null
                val preferOrdinal = source.readInt()
                val prefer = PreferEncrypt.entries.getOrElse(preferOrdinal) { PreferEncrypt.NOPREFERENCE }
                source.setDataPosition(startPosition + parcelableSize)
                return AutocryptPeerUpdate(keyData, effectiveDate, prefer)
            }

            override fun newArray(size: Int): Array<AutocryptPeerUpdate?> = arrayOfNulls(size)
        }
    }
}
