package ltechnologies.onionphone.pgpshield

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dagger.hilt.android.EntryPointAccessors
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.di.ProviderEntryPoint
import ltechnologies.onionphone.pgpshield.engine.AlgorithmLabels
import ltechnologies.onionphone.pgpshield.engine.BouncyCastleProviderHolder
import ltechnologies.onionphone.pgpshield.engine.KeyAlgorithmType
import ltechnologies.onionphone.pgpshield.engine.KeyRingExporter
import ltechnologies.onionphone.pgpshield.engine.SubkeyType
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class VaultIntegrationDeviceTest {
    private lateinit var keyRepository: KeyRepository
    private lateinit var cryptoOperations: CryptoOperations

    @Before
    fun setUp() {
        BouncyCastleProviderHolder.ensureRegistered()
        val app = InstrumentationRegistry.getInstrumentation().targetContext.applicationContext
        val entryPoint = EntryPointAccessors.fromApplication(app, ProviderEntryPoint::class.java)
        keyRepository = entryPoint.keyRepository()
        cryptoOperations = entryPoint.cryptoOperations()
    }

    @Test
    fun vault_addSubkeyAndEncryptRoundTrip() = runBlocking {
        val passphrase = "vault-waydroid-test".toCharArray()
        try {
            val generated = cryptoOperations.generateKey(
                userId = "Waydroid Vault <vault@pgpshield.test>",
                passphrase = passphrase,
                algorithmType = KeyAlgorithmType.RSA,
                rsaBits = 3072,
            )
            val label = AlgorithmLabels.forKeyType(KeyAlgorithmType.RSA, 3072)
            val info = keyRepository.importGeneratedKeyRing(
                generated.publicArmored,
                generated.secretArmored,
                label,
            )
            val subkeysBefore = keyRepository.getKeyDetail(info.masterKeyId)!!.subkeys.size

            val secret = keyRepository.getArmoredSecret(info.masterKeyId)
                ?: error("Secret key missing after import")
            val updated = cryptoOperations.addSubkey(
                secretArmored = secret,
                passphrase = passphrase,
                subkeyType = SubkeyType.ENCRYPT_RSA,
                rsaBits = 3072,
            )
            val public = KeyRingExporter.publicArmoredFromSecret(updated)
            keyRepository.replaceSecretKeyRing(info.masterKeyId, updated, public)

            val subkeysAfter = keyRepository.getKeyDetail(info.masterKeyId)!!.subkeys.size
            assertTrue("subkey count should increase", subkeysAfter > subkeysBefore)

            val publicArmored = keyRepository.getArmoredPublic(info.masterKeyId)
                ?: error("Public key missing after subkey add")
            val encrypted = cryptoOperations.encrypt(
                plaintext = "waydroid-vault-encrypt".toByteArray(Charsets.UTF_8),
                recipientPublicArmored = listOf(publicArmored),
            )
            val decrypted = cryptoOperations.decrypt(
                ciphertext = encrypted.ciphertext,
                secretArmored = updated,
                passphrase = passphrase,
            )
            assertTrue(
                String(decrypted.plaintext, Charsets.UTF_8).contains("waydroid-vault-encrypt"),
            )
        } finally {
            passphrase.fill('\u0000')
        }
    }
}
