package ltechnologies.onionphone.pgpshield.data

import ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo
import ltechnologies.onionphone.pgpshield.engine.model.SubkeyInfo
import kotlinx.coroutines.flow.Flow

/**
 * Lightweight summary of a stored key ring for list and search UI.
 *
 * @property masterKeyId 64-bit OpenPGP master key identifier.
 * @property fingerprint Space-grouped primary key fingerprint.
 * @property primaryUserId Preferred user id string, if any.
 * @property isSecret Whether a secret key ring is stored locally.
 * @property isRevoked Whether the key is marked revoked in metadata or on-disk.
 * @property primaryAlgorithm Human-readable algorithm label for the primary key.
 * @property createdAt Import or generation timestamp (epoch millis).
 * @property subkeyCount Number of subkeys in the ring.
 * @property trustLevel Local trust: 0=unknown, 1=marginal, 2=full, 3=never.
 */
data class KeySummary(
    val masterKeyId: Long,
    val fingerprint: String,
    val primaryUserId: String?,
    val isSecret: Boolean,
    val isRevoked: Boolean,
    val primaryAlgorithm: String = "RSA 3072",
    val createdAt: Long = 0L,
    val subkeyCount: Int = 1,
    val trustLevel: Int = 0,
)

/**
 * Full key detail including subkey metadata from the PGP engine.
 *
 * @property summary List-oriented key summary from the database.
 * @property subkeys Parsed subkey information from the armored blob.
 */
data class KeyDetail(
    val summary: KeySummary,
    val subkeys: List<SubkeyInfo>,
)

/**
 * Domain repository for PGP key ring lifecycle: import, export, certification,
 * keyserver sync, and trust management.
 *
 * Combines Room metadata, encrypted blob storage, and the PGP engine. UI and service
 * layers depend on this interface rather than [KeyRepositoryImpl].
 */
interface KeyRepository {
    /** Observes all stored keys with primary user ids, ordered by creation time. */
    fun observeKeys(): Flow<List<KeySummary>>

    /**
     * Imports an armored key ring from file or clipboard.
     *
     * @param armored UTF-8 armored key block.
     * @param secret `true` for secret key material, `false` for public-only.
     */
    suspend fun importKeyRing(armored: ByteArray, secret: Boolean): KeyRingInfo

    /**
     * Persists a newly generated key pair (separate public and secret armored blocks).
     */
    suspend fun importGeneratedKeyRing(
        publicArmored: ByteArray,
        secretArmored: ByteArray,
        primaryAlgorithm: String,
    ): KeyRingInfo

    /** Loads key detail and subkeys, or `null` if missing or blob is unreadable. */
    suspend fun getKeyDetail(keyId: Long): KeyDetail?

    /** Returns the raw armored blob (secret or public) for [keyId]. */
    suspend fun exportKeyRing(keyId: Long): ByteArray

    /** Marks [keyId] as revoked in local metadata (does not rewrite the blob). */
    suspend fun revokeKey(keyId: Long)

    /** Deletes database rows and removes associated blob files. */
    suspend fun deleteKey(keyId: Long)

    /** Searches keys by fingerprint fragment. */
    suspend fun search(query: String): List<KeySummary>

    /** Returns armored secret key bytes, or `null` if not a secret key or missing. */
    suspend fun getArmoredSecret(keyId: Long): ByteArray?

    /** Returns armored public key bytes, deriving from secret if no public blob exists. */
    suspend fun getArmoredPublic(keyId: Long): ByteArray?

    /** Replaces on-disk secret and public blobs after passphrase or uid changes. */
    suspend fun replaceSecretKeyRing(keyId: Long, secretArmored: ByteArray, publicArmored: ByteArray)

    /** Convenience wrapper around [replaceSecretKeyRing] after passphrase change. */
    suspend fun changePassphrase(keyId: Long, newSecretArmored: ByteArray)

    /** Generates an armored revocation certificate for [keyId]. */
    suspend fun generateRevocationCert(keyId: Long, passphrase: CharArray, reasonText: String = ""): ByteArray

    /**
     * Certifies [targetKeyId] with [certifierKeyId] and embeds the signature in stored public material.
     */
    suspend fun certifyKey(
        certifierKeyId: Long,
        targetKeyId: Long,
        certifierPassphrase: CharArray,
        userId: String,
    ): ByteArray

    /** Refreshes public key material from a keyserver and updates metadata. */
    suspend fun refreshKeyFromKeyserver(keyId: Long, baseUrl: String): KeyRingInfo

    /** Adds a user id to a secret key ring and re-persists blobs and uid rows. */
    suspend fun addUserId(keyId: Long, passphrase: CharArray, userId: String)

    /** Sets local trust level (0–3) for [keyId]. */
    suspend fun setTrustLevel(keyId: Long, trustLevel: Int)

    /** Uploads the public key for [keyId] to [baseUrl]. */
    suspend fun uploadPublicKey(keyId: Long, baseUrl: String)

    /**
     * Removes database entries whose blob files are missing from disk.
     *
     * @return Count of keys removed.
     */
    suspend fun purgeMissingBlobKeys(): Int
}
