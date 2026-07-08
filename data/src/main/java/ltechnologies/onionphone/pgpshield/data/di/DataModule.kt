package ltechnologies.onionphone.pgpshield.data

import android.content.Context
import androidx.room.Room
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
     */
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AppDatabase =
        Room.databaseBuilder(context, AppDatabase::class.java, "pgp_shield.db")
            .fallbackToDestructiveMigration() // ponytail: v1 only; add migrations when schema stabilizes
            .build()

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
