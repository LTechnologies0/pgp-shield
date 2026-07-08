package ltechnologies.onionphone.pgpshield.api

import android.os.Parcelable
import kotlinx.parcelize.Parcelize

/**
 * Parcelable request/response types for the PGP Shield IPC API.
 *
 * Used across process boundaries with AIDL and Kotlin [PgpShieldClient] wrappers.
 */

/**
 * Identifies the calling Android app for permission checks.
 *
 * @property packageName Application package name.
 * @property uid Linux uid of the caller at bind time.
 */
@Parcelize
data class CallerIdentity(
    val packageName: String,
    val uid: Int,
) : Parcelable

/** Result of a permission check for an API caller. */
enum class PermissionState {
    /** Caller may invoke crypto methods immediately. */
    GRANTED,

    /** Caller is blocked. */
    DENIED,

    /** User must approve access in the host app UI. */
    REQUIRES_USER_CONSENT,
}

/**
 * Encrypt request passed to the bound service.
 *
 * @property caller Identity of the requesting app.
 * @property plaintext UTF-8 or binary payload to encrypt.
 * @property recipientKeyIds OpenPGP recipient master key ids.
 * @property asciiArmor Whether output should be ASCII-armored.
 */
@Parcelize
data class EncryptRequestParcel(
    val caller: CallerIdentity,
    val plaintext: ByteArray,
    val recipientKeyIds: LongArray,
    val asciiArmor: Boolean = true,
) : Parcelable

/**
 * Decrypt request passed to the bound service.
 *
 * @property caller Identity of the requesting app.
 * @property ciphertext Armored or binary OpenPGP message.
 * @property decryptKeyId Secret key id to decrypt with.
 * @property passphrase Optional unlock passphrase for the secret key.
 */
@Parcelize
data class DecryptRequestParcel(
    val caller: CallerIdentity,
    val ciphertext: ByteArray,
    val decryptKeyId: Long,
    val passphrase: CharArray? = null,
) : Parcelable

/**
 * Sign request passed to the bound service.
 *
 * @property caller Identity of the requesting app.
 * @property data Payload bytes to sign.
 * @property signKeyId Secret signing key id.
 * @property passphrase Optional unlock passphrase for the secret key.
 */
@Parcelize
data class SignRequestParcel(
    val caller: CallerIdentity,
    val data: ByteArray,
    val signKeyId: Long,
    val passphrase: CharArray? = null,
) : Parcelable

/**
 * Unified success/failure result for encrypt, decrypt, and sign operations.
 *
 * @property success Whether the operation completed without error.
 * @property output Result bytes (ciphertext, plaintext, or signature) when [success] is true.
 * @property errorMessage Human-readable error when [success] is false.
 * @property requiresUserInteraction True when the host must prompt (e.g. passphrase).
 */
@Parcelize
data class CryptoResultParcel(
    val success: Boolean,
    val output: ByteArray? = null,
    val errorMessage: String? = null,
    val requiresUserInteraction: Boolean = false,
) : Parcelable

/**
 * Minimal key metadata exposed to API clients.
 *
 * @property masterKeyId 64-bit OpenPGP master key id.
 * @property fingerprint Display fingerprint.
 * @property primaryUserId Primary uid string, if present.
 * @property isSecret Whether a secret key exists locally (clients typically see public only).
 */
@Parcelize
data class KeySummaryParcel(
    val masterKeyId: Long,
    val fingerprint: String,
    val primaryUserId: String?,
    val isSecret: Boolean,
) : Parcelable
