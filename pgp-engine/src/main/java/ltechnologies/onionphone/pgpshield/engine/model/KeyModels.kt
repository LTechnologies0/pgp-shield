package ltechnologies.onionphone.pgpshield.engine.model

/**
 * Immutable domain models for OpenPGP key ring metadata.
 *
 * Populated by [ltechnologies.onionphone.pgpshield.engine.KeyRingReader] and consumed
 * by the app layer and [ltechnologies.onionphone.pgpshield.engine.PgpAlgorithmPolicy].
 */

import java.time.Instant

/**
 * Metadata for a single public or secret subkey in a key ring.
 *
 * @property keyId 64-bit OpenPGP key ID.
 * @property fingerprint Space-separated uppercase hex fingerprint.
 * @property algorithm OpenPGP public-key algorithm tag.
 * @property creationTime Key creation instant.
 * @property expirationTime Expiration instant, or `null` if the key does not expire.
 * @property isRevoked Whether the key carries a revocation signature.
 * @property flags Aggregated OpenPGP key-flags bitmask (certify, sign, encrypt, auth).
 */
data class SubkeyInfo(
    val keyId: Long,
    val fingerprint: String,
    val algorithm: Int,
    val creationTime: Instant,
    val expirationTime: Instant?,
    val isRevoked: Boolean,
    val flags: Int,
)

/**
 * User ID entry on the master key.
 *
 * @property userId RFC 4880 user ID string.
 * @property isPrimary Whether this ID is marked primary in self-certifications.
 */
data class UserIdInfo(
    val userId: String,
    val isPrimary: Boolean,
)

/**
 * Summary of an OpenPGP public or secret key ring.
 *
 * @property masterKeyId 64-bit ID of the primary (certifying) key.
 * @property fingerprint Master key fingerprint (formatted hex).
 * @property userIds All user IDs on the master key.
 * @property subkeys Master and subkey metadata in ring order.
 * @property isSecret `true` when parsed from a secret key ring.
 * @property isRevoked Whether the master key is revoked.
 */
data class KeyRingInfo(
    val masterKeyId: Long,
    val fingerprint: String,
    val userIds: List<UserIdInfo>,
    val subkeys: List<SubkeyInfo>,
    val isSecret: Boolean,
    val isRevoked: Boolean,
)
