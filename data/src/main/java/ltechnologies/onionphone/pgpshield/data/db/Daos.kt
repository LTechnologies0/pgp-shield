package ltechnologies.onionphone.pgpshield.data.db

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

/**
 * Room data access objects for PGP Shield persistence.
 */

/** CRUD and search access for [KeyRingEntity] rows. */
@Dao
interface KeyRingDao {
    /** Observes all key rings ordered by [KeyRingEntity.createdAt] descending. */
    @Query("SELECT * FROM key_rings ORDER BY createdAt DESC")
    fun observeAll(): Flow<List<KeyRingEntity>>

    /** Returns all key rings (non-reactive). */
    @Query("SELECT * FROM key_rings")
    suspend fun getAll(): List<KeyRingEntity>

    /** Finds a key ring by [keyId], or `null` if absent. */
    @Query("SELECT * FROM key_rings WHERE masterKeyId = :keyId LIMIT 1")
    suspend fun getById(keyId: Long): KeyRingEntity?

    /** Inserts or replaces a key ring row. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entity: KeyRingEntity)

    /** Deletes the key ring with [keyId]. */
    @Query("DELETE FROM key_rings WHERE masterKeyId = :keyId")
    suspend fun delete(keyId: Long)

    /** Sets [KeyRingEntity.isRevoked] for [keyId]. */
    @Query("UPDATE key_rings SET isRevoked = 1 WHERE masterKeyId = :keyId")
    suspend fun markRevoked(keyId: Long)

    /** Updates [KeyRingEntity.trustLevel] for [keyId]. */
    @Query("UPDATE key_rings SET trustLevel = :level WHERE masterKeyId = :keyId")
    suspend fun setTrustLevel(keyId: Long, level: Int)

    /** Substring search on [KeyRingEntity.fingerprint]. */
    @Query("SELECT * FROM key_rings WHERE fingerprint LIKE '%' || :query || '%'")
    suspend fun search(query: String): List<KeyRingEntity>
}

/** Access to user id rows linked to key rings. */
@Dao
interface UserIdDao {
    /** Observes all user id rows. */
    @Query("SELECT * FROM user_ids")
    fun observeAll(): Flow<List<UserIdEntity>>

    /** Returns all user ids for [keyId]. */
    @Query("SELECT * FROM user_ids WHERE masterKeyId = :keyId")
    suspend fun forKey(keyId: Long): List<UserIdEntity>

    /** Case-insensitive substring match on [UserIdEntity.userId]. */
    @Query("SELECT * FROM user_ids WHERE LOWER(userId) LIKE '%' || LOWER(:fragment) || '%'")
    suspend fun findByUserIdFragment(fragment: String): List<UserIdEntity>

    /** Inserts or replaces a batch of user id rows. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(entities: List<UserIdEntity>)

    /** Removes all user ids for [keyId]. */
    @Query("DELETE FROM user_ids WHERE masterKeyId = :keyId")
    suspend fun deleteForKey(keyId: Long)
}

/** Grants and revokes IPC API access for client apps. */
@Dao
interface ApiAppDao {
    /** Returns the grant row for [packageName], if any. */
    @Query("SELECT * FROM api_apps WHERE packageName = :packageName")
    suspend fun get(packageName: String): ApiAppEntity?

    /** Records or updates API access for an app. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun grant(entity: ApiAppEntity)

    /** Revokes API access for [packageName]. */
    @Query("DELETE FROM api_apps WHERE packageName = :packageName")
    suspend fun revoke(packageName: String)

    /** Observes all granted API client apps. */
    @Query("SELECT * FROM api_apps")
    fun observeAll(): Flow<List<ApiAppEntity>>
}

/** Per-app allowlist of key ids permitted for IPC crypto. */
@Dao
interface ApiAllowedKeyDao {
    /** Returns key ids [packageName] may use. */
    @Query("SELECT keyId FROM api_allowed_keys WHERE packageName = :packageName")
    suspend fun allowedKeyIds(packageName: String): List<Long>

    /** Adds an allowed key for an app. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entity: ApiAllowedKeyEntity)

    /** Clears all allowed keys for [packageName]. */
    @Query("DELETE FROM api_allowed_keys WHERE packageName = :packageName")
    suspend fun clearForApp(packageName: String)
}

/** Per messaging-app overlay configuration. */
@Dao
interface OverlayConfigDao {
    /** Loads overlay config for [packageName]. */
    @Query("SELECT * FROM overlay_app_config WHERE packageName = :packageName")
    suspend fun get(packageName: String): OverlayAppConfigEntity?

    /** Observes enabled overlay configs only. */
    @Query("SELECT * FROM overlay_app_config WHERE enabled = 1")
    fun observeEnabled(): Flow<List<OverlayAppConfigEntity>>

    /** Observes all overlay configs sorted by package name. */
    @Query("SELECT * FROM overlay_app_config ORDER BY packageName")
    fun observeAll(): Flow<List<OverlayAppConfigEntity>>

    /** Inserts or updates overlay config for an app. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: OverlayAppConfigEntity)

    /** Removes overlay config for [packageName]. */
    @Query("DELETE FROM overlay_app_config WHERE packageName = :packageName")
    suspend fun delete(packageName: String)
}

/** CRUD for padding cover templates. */
@Dao
interface PaddingTemplateDao {
    /** Observes all padding templates. */
    @Query("SELECT * FROM padding_templates")
    fun observeAll(): Flow<List<PaddingTemplateEntity>>

    /** Inserts or replaces a padding template. */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(entity: PaddingTemplateEntity)
}
