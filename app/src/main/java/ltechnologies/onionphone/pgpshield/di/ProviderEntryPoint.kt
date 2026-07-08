package ltechnologies.onionphone.pgpshield.di

/**
 * Hilt entry point for components that live outside the injection graph.
 */

import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.db.UserIdDao

/**
 * Exposes singleton dependencies to non-injected classes such as
 * [android.content.ContentProvider]s via `EntryPointAccessors`.
 */
@EntryPoint
@InstallIn(SingletonComponent::class)
interface ProviderEntryPoint {
    /** Provides the DAO used to query OpenPGP user identities. */
    fun userIdDao(): UserIdDao

    /** Provides the repository managing stored key material. */
    fun keyRepository(): KeyRepository

    /** Provides the cryptographic operations facade. */
    fun cryptoOperations(): CryptoOperations
}
