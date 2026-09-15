package org.openintents.openpgp

/**
 * Parcelable signature-verification result for the OpenPGP API IPC contract.
 *
 * Wire-compatible with openpgp-api [org.openintents.openpgp.OpenPgpSignatureResult]
 * so clients (K-9, FairEmail) can unmarshal `RESULT_SIGNATURE` extras.
 */

import android.os.Parcel
import android.os.Parcelable
import java.util.Date

/**
 * @property result One of the `RESULT_*` status constants.
 * @property keyId Signer key ID when known; `0` otherwise.
 */
class OpenPgpSignatureResult private constructor(
    private val result: Int,
    private val keyId: Long,
    private val primaryUserId: String? = null,
    private val userIds: List<String>? = null,
    private val confirmedUserIds: List<String>? = null,
    private val senderStatusResult: SenderStatusResult? = null,
    private val signatureTimestamp: Date? = null,
    private val autocryptPeerResult: AutocryptPeerResult? = null,
) : Parcelable {

    fun getResult(): Int = result

    fun getKeyId(): Long = keyId

    fun getPrimaryUserId(): String? = primaryUserId

    fun getUserIds(): List<String>? = userIds

    fun getConfirmedUserIds(): List<String>? = confirmedUserIds

    fun getSenderStatusResult(): SenderStatusResult? = senderStatusResult

    fun getSignatureTimestamp(): Date? = signatureTimestamp

    fun getAutocryptPeerResult(): AutocryptPeerResult? = autocryptPeerResult

    override fun describeContents(): Int = 0

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeInt(PARCELABLE_VERSION)
        val sizePosition = dest.dataPosition()
        dest.writeInt(0)
        val startPosition = dest.dataPosition()
        // version 1
        dest.writeInt(result)
        dest.writeByte(0) // deprecated signatureOnly
        dest.writeString(primaryUserId)
        dest.writeLong(keyId)
        // version 2
        dest.writeStringList(userIds)
        // version 3
        writeEnumWithNull(dest, senderStatusResult)
        dest.writeStringList(confirmedUserIds)
        // version 4
        if (signatureTimestamp != null) {
            dest.writeInt(1)
            dest.writeLong(signatureTimestamp.time)
        } else {
            dest.writeInt(0)
        }
        // version 5
        writeEnumWithNull(dest, autocryptPeerResult)
        val parcelableSize = dest.dataPosition() - startPosition
        dest.setDataPosition(sizePosition)
        dest.writeInt(parcelableSize)
        dest.setDataPosition(startPosition + parcelableSize)
    }

    enum class SenderStatusResult {
        UNKNOWN,
        USER_ID_CONFIRMED,
        USER_ID_UNCONFIRMED,
        USER_ID_MISSING,
    }

    enum class AutocryptPeerResult {
        OK,
        NEW,
        MISMATCH,
    }

    companion object {
        const val PARCELABLE_VERSION = 5

        const val RESULT_NO_SIGNATURE = -1
        const val RESULT_INVALID_SIGNATURE = 0
        const val RESULT_VALID_KEY_CONFIRMED = 1
        const val RESULT_KEY_MISSING = 2
        const val RESULT_VALID_KEY_UNCONFIRMED = 3
        const val RESULT_INVALID_KEY_REVOKED = 4
        const val RESULT_INVALID_KEY_EXPIRED = 5
        const val RESULT_INVALID_KEY_INSECURE = 6
        const val RESULT_INVALID_NOT_INTENDED_RECIPIENT = 7

        @JvmStatic
        fun createWithNoSignature(): OpenPgpSignatureResult =
            OpenPgpSignatureResult(RESULT_NO_SIGNATURE, 0L)

        @JvmStatic
        fun createWithInvalidSignature(): OpenPgpSignatureResult =
            OpenPgpSignatureResult(RESULT_INVALID_SIGNATURE, 0L)

        @JvmStatic
        fun createWithKeyMissing(keyId: Long): OpenPgpSignatureResult =
            OpenPgpSignatureResult(RESULT_KEY_MISSING, keyId)

        @JvmStatic
        @JvmOverloads
        fun createWithValidSignature(
            keyId: Long,
            confirmed: Boolean = false,
            primaryUserId: String? = null,
            userIds: List<String>? = null,
            senderStatusResult: SenderStatusResult? = null,
            autocryptPeerResult: AutocryptPeerResult? = null,
            signatureTimestamp: Date? = null,
        ): OpenPgpSignatureResult {
            val senderStatus = senderStatusResult ?: when {
                primaryUserId.isNullOrBlank() -> SenderStatusResult.USER_ID_MISSING
                confirmed -> SenderStatusResult.USER_ID_CONFIRMED
                else -> SenderStatusResult.USER_ID_UNCONFIRMED
            }
            return OpenPgpSignatureResult(
                result = if (confirmed) RESULT_VALID_KEY_CONFIRMED else RESULT_VALID_KEY_UNCONFIRMED,
                keyId = keyId,
                primaryUserId = primaryUserId,
                userIds = userIds ?: primaryUserId?.let { listOf(it) },
                confirmedUserIds = if (confirmed && !primaryUserId.isNullOrBlank()) {
                    listOf(primaryUserId)
                } else {
                    null
                },
                senderStatusResult = senderStatus,
                signatureTimestamp = signatureTimestamp,
                autocryptPeerResult = autocryptPeerResult,
            )
        }

        @JvmStatic
        @JvmOverloads
        fun createWithRevokedKey(keyId: Long, primaryUserId: String? = null): OpenPgpSignatureResult =
            OpenPgpSignatureResult(
                result = RESULT_INVALID_KEY_REVOKED,
                keyId = keyId,
                primaryUserId = primaryUserId,
                userIds = primaryUserId?.let { listOf(it) },
                senderStatusResult = SenderStatusResult.UNKNOWN,
            )

        @JvmStatic
        @JvmOverloads
        fun createWithExpiredKey(keyId: Long, primaryUserId: String? = null): OpenPgpSignatureResult =
            OpenPgpSignatureResult(
                result = RESULT_INVALID_KEY_EXPIRED,
                keyId = keyId,
                primaryUserId = primaryUserId,
                userIds = primaryUserId?.let { listOf(it) },
                senderStatusResult = SenderStatusResult.UNKNOWN,
            )

        @JvmStatic
        @JvmOverloads
        fun createWithInsecureKey(keyId: Long, primaryUserId: String? = null): OpenPgpSignatureResult =
            OpenPgpSignatureResult(
                result = RESULT_INVALID_KEY_INSECURE,
                keyId = keyId,
                primaryUserId = primaryUserId,
                userIds = primaryUserId?.let { listOf(it) },
                senderStatusResult = SenderStatusResult.UNKNOWN,
            )

        /**
         * Cryptographically valid signature whose signing key UIDs do not include the
         * mail From: address ([EXTRA_SENDER_ADDRESS] / openpgp-api).
         */
        @JvmStatic
        @JvmOverloads
        fun createWithNotIntendedRecipient(
            keyId: Long,
            primaryUserId: String? = null,
            userIds: List<String>? = null,
            signatureTimestamp: Date? = null,
            autocryptPeerResult: AutocryptPeerResult? = null,
        ): OpenPgpSignatureResult =
            OpenPgpSignatureResult(
                result = RESULT_INVALID_NOT_INTENDED_RECIPIENT,
                keyId = keyId,
                primaryUserId = primaryUserId,
                userIds = userIds ?: primaryUserId?.let { listOf(it) },
                senderStatusResult = SenderStatusResult.USER_ID_MISSING,
                signatureTimestamp = signatureTimestamp,
                autocryptPeerResult = autocryptPeerResult,
            )

        private fun writeEnumWithNull(dest: Parcel, enumValue: Enum<*>?) {
            if (enumValue == null) {
                dest.writeInt(-1)
            } else {
                dest.writeInt(enumValue.ordinal)
            }
        }

        private fun <T : Enum<T>> readEnumWithNullAndFallback(
            source: Parcel,
            enumValues: Array<T>,
            fallback: T?,
        ): T? {
            val valueOrdinal = source.readInt()
            if (valueOrdinal == -1) return null
            if (valueOrdinal >= enumValues.size) return fallback
            return enumValues[valueOrdinal]
        }

        @JvmField
        val CREATOR = object : Parcelable.Creator<OpenPgpSignatureResult> {
            override fun createFromParcel(source: Parcel): OpenPgpSignatureResult {
                val version = source.readInt()
                val parcelableSize = source.readInt()
                val startPosition = source.dataPosition()

                val result = source.readInt()
                source.readByte() // signatureOnly
                val primaryUserId = source.readString()
                val keyId = source.readLong()
                val userIds = if (version > 1) source.createStringArrayList() else null
                val senderStatusResult: SenderStatusResult?
                val confirmedUserIds: List<String>?
                if (version > 2) {
                    senderStatusResult = readEnumWithNullAndFallback(
                        source,
                        SenderStatusResult.entries.toTypedArray(),
                        SenderStatusResult.UNKNOWN,
                    )
                    confirmedUserIds = source.createStringArrayList()
                } else {
                    senderStatusResult = SenderStatusResult.UNKNOWN
                    confirmedUserIds = null
                }
                val signatureTimestamp = if (version > 3 && source.readInt() > 0) {
                    Date(source.readLong())
                } else {
                    null
                }
                val autocryptPeerResult = if (version > 4) {
                    readEnumWithNullAndFallback(
                        source,
                        AutocryptPeerResult.entries.toTypedArray(),
                        null,
                    )
                } else {
                    null
                }

                source.setDataPosition(startPosition + parcelableSize)
                return OpenPgpSignatureResult(
                    result = result,
                    keyId = keyId,
                    primaryUserId = primaryUserId,
                    userIds = userIds,
                    confirmedUserIds = confirmedUserIds,
                    senderStatusResult = senderStatusResult,
                    signatureTimestamp = signatureTimestamp,
                    autocryptPeerResult = autocryptPeerResult,
                )
            }

            override fun newArray(size: Int): Array<OpenPgpSignatureResult?> = arrayOfNulls(size)
        }
    }
}
