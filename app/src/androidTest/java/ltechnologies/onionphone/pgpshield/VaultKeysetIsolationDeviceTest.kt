package ltechnologies.onionphone.pgpshield

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dagger.hilt.android.EntryPointAccessors
import ltechnologies.onionphone.pgpshield.data.vault.KeyBlobStore
import ltechnologies.onionphone.pgpshield.di.ProviderEntryPoint
import ltechnologies.onionphone.pgpshield.security.AppLockManager
import org.junit.Assert.assertArrayEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Reproduces the 1.0.3 upgrade failure mode: default EncryptedFile Tink keyset
 * poisoned / encrypted under a different MasterKey → [javax.crypto.AEADBadTagException]
 * on write when keysets are not isolated.
 */
@RunWith(AndroidJUnit4::class)
class VaultKeysetIsolationDeviceTest {
    private lateinit var context: Context
    private lateinit var blobStore: KeyBlobStore
    private lateinit var appLock: AppLockManager

    @Before
    fun setUp() {
        context = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val entryPoint = EntryPointAccessors.fromApplication(context, ProviderEntryPoint::class.java)
        blobStore = entryPoint.keyBlobStore()
        appLock = entryPoint.appLockManager()
        appLock.markUnlocked()
    }

    @Test
    fun writeSucceedsWhenDefaultEncryptedFileKeysetIsPoisoned() {
        // Simulate leftover AndroidX default keyset that cannot be opened with vault MasterKey v2.
        @Suppress("ApplySharedPref")
        context.getSharedPreferences(DEFAULT_KEYSET_PREF, Context.MODE_PRIVATE)
            .edit()
            .putString(DEFAULT_KEYSET_ALIAS, "not-a-valid-tink-keyset")
            .commit()

        val payload = "AEAD-isolation-probe".toByteArray(Charsets.UTF_8)
        val path = blobStore.write(keyId = 0xAEADL, data = payload)
        val roundTrip = blobStore.read(path)
        assertArrayEquals(payload, roundTrip)
        blobStore.delete(path)
    }

    companion object {
        private const val DEFAULT_KEYSET_PREF = "__androidx_security_crypto_encrypted_file_pref__"
        private const val DEFAULT_KEYSET_ALIAS = "__androidx_security_crypto_encrypted_file_keyset__"
    }
}
