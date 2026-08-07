package ltechnologies.onionphone.pgpshield.di

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import javax.inject.Singleton
import ltechnologies.onionphone.pgpshield.data.security.VaultAccessPolicy
import ltechnologies.onionphone.pgpshield.security.AppLockManager

@Module
@InstallIn(SingletonComponent::class)
abstract class SecurityModule {
    @Binds
    @Singleton
    abstract fun bindVaultAccessPolicy(impl: AppLockManager): VaultAccessPolicy
}
