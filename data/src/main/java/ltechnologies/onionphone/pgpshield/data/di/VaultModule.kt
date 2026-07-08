package ltechnologies.onionphone.pgpshield.data.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import ltechnologies.onionphone.pgpshield.data.vault.EncryptedBlobStore
import ltechnologies.onionphone.pgpshield.data.vault.KeyBlobStore
import javax.inject.Singleton

/**
 * Hilt bindings for encrypted key blob storage.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class VaultModule {
    /**
     * Binds [EncryptedBlobStore] as the app-wide [KeyBlobStore] implementation.
     */
    @Binds
    @Singleton
    abstract fun bindKeyBlobStore(impl: EncryptedBlobStore): KeyBlobStore
}
