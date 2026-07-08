package ltechnologies.onionphone.pgpshield.data.db

import androidx.room.Database
import androidx.room.RoomDatabase

/**
 * Room database for PGP Shield: key metadata, API permissions, overlay settings, and templates.
 *
 * Schema version 6; armored key bytes are stored outside Room in [KeyBlobStore].
 */
@Database(
    entities = [
        KeyRingEntity::class,
        UserIdEntity::class,
        ApiAppEntity::class,
        ApiAllowedKeyEntity::class,
        OverlayAppConfigEntity::class,
        PaddingTemplateEntity::class,
    ],
    version = 6,
    exportSchema = true,
)
abstract class AppDatabase : RoomDatabase() {
    /** DAO for key ring metadata. */
    abstract fun keyRingDao(): KeyRingDao

    /** DAO for user id rows. */
    abstract fun userIdDao(): UserIdDao

    /** DAO for granted API client apps. */
    abstract fun apiAppDao(): ApiAppDao

    /** DAO for per-app allowed key ids. */
    abstract fun apiAllowedKeyDao(): ApiAllowedKeyDao

    /** DAO for messaging overlay configuration. */
    abstract fun overlayConfigDao(): OverlayConfigDao

    /** DAO for padding encoding templates. */
    abstract fun paddingTemplateDao(): PaddingTemplateDao
}
