package ltechnologies.onionphone.pgpshield.data

import android.content.Context
import androidx.room.Room
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import ltechnologies.onionphone.pgpshield.data.db.AppDatabase
import javax.inject.Singleton

/**
 * Hilt module providing the Room [AppDatabase] singleton and DAO accessors.
 */
@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {
    /**
     * Builds the encrypted-metadata SQLite database for keys, API grants, and overlay config.
     *
     * Migrations 5→6 and 6→7 preserve data; older versions still fall back to destructive
     * recreate (pre-stable schemas).
     */
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AppDatabase =
        Room.databaseBuilder(context, AppDatabase::class.java, "pgp_shield.db")
            .addMigrations(MIGRATION_5_6, MIGRATION_6_7)
            .fallbackToDestructiveMigrationFrom(1, 2, 3, 4)
            .build()

    private val MIGRATION_5_6 = object : Migration(5, 6) {
        override fun migrate(db: SupportSQLiteDatabase) {
            // v6 matches current entity set; no structural SQL required when upgrading from v5.
        }
    }

    private val MIGRATION_6_7 = object : Migration(6, 7) {
        override fun migrate(db: SupportSQLiteDatabase) {
            db.execSQL(
                "ALTER TABLE key_rings ADD COLUMN hardwareManagedPassphrase INTEGER NOT NULL DEFAULT 0",
            )
        }
    }

    /** @see AppDatabase.apiAppDao */
    @Provides fun provideApiAppDao(db: AppDatabase) = db.apiAppDao()

    /** @see AppDatabase.apiAllowedKeyDao */
    @Provides fun provideApiAllowedKeyDao(db: AppDatabase) = db.apiAllowedKeyDao()

    /** @see AppDatabase.userIdDao */
    @Provides fun provideUserIdDao(db: AppDatabase) = db.userIdDao()

    /** @see AppDatabase.overlayConfigDao */
    @Provides fun provideOverlayConfigDao(db: AppDatabase) = db.overlayConfigDao()

    /** @see AppDatabase.paddingTemplateDao */
    @Provides fun providePaddingTemplateDao(db: AppDatabase) = db.paddingTemplateDao()
}

/**
 * Hilt bindings for data-layer repositories.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class RepositoryModule {
    /** Binds [KeyRepositoryImpl] as the app-wide [KeyRepository]. */
    @Binds
    @Singleton
    abstract fun bindKeyRepository(impl: KeyRepositoryImpl): KeyRepository
}
