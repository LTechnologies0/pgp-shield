package ltechnologies.onionphone.pgpshield.data

import androidx.room.Room
import ltechnologies.onionphone.pgpshield.data.db.AppDatabase
import ltechnologies.onionphone.pgpshield.engine.BouncyCastleProviderHolder
import ltechnologies.onionphone.pgpshield.engine.GenerateKeyRequest
import ltechnologies.onionphone.pgpshield.engine.KeyAlgorithmType
import ltechnologies.onionphone.pgpshield.engine.KeyGenerator
import ltechnologies.onionphone.pgpshield.engine.RevocationCertApplier
import java.io.File
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class KeyRepositoryFlowTest {
    private lateinit var database: AppDatabase
    private lateinit var repository: KeyRepositoryImpl

    @Before
    fun setUp() {
        BouncyCastleProviderHolder.ensureRegistered()
        database = Room.inMemoryDatabaseBuilder(
            RuntimeEnvironment.getApplication(),
            AppDatabase::class.java,
        ).allowMainThreadQueries().build()
        repository = KeyRepositoryImpl(database, InMemoryBlobStore(), KeyserverClient())
    }

    @After
    fun tearDown() {
        database.close()
    }

    @Test
    fun import_observe_delete() = runBlocking {
        val pass = "repo-pass".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest("Repo <repo@example.com>", pass, KeyAlgorithmType.RSA, 3072),
            )
            val info = repository.importGeneratedKeyRing(
                generated.publicArmored,
                generated.secretArmored,
                "RSA 3072",
            )
            val keys = repository.observeKeys().first()
            assertEquals(1, keys.size)
            assertEquals(info.masterKeyId, keys.single().masterKeyId)
            assertTrue(keys.single().isSecret)

            repository.deleteKey(info.masterKeyId)
            assertNull(database.keyRingDao().getById(info.masterKeyId))
            assertEquals(0, repository.observeKeys().first().size)
        } finally {
            pass.fill('\u0000')
        }
    }

    @Test
    fun upload_refresh_from_keyserver() = runBlocking {
        val pass = "hkp-pass".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest("HKP <hkp@example.com>", pass, KeyAlgorithmType.RSA, 3072),
            )
            val info = repository.importGeneratedKeyRing(
                generated.publicArmored,
                generated.secretArmored,
                "RSA 3072",
            )
            val public = repository.getArmoredPublic(info.masterKeyId)!!
            FakeKeyserver(public).use { server ->
                repository.uploadPublicKey(info.masterKeyId, server.baseUrl)
                assertNotNull(server.uploadedKey)
                val refreshed = repository.refreshKeyFromKeyserver(info.masterKeyId, server.baseUrl)
                assertEquals(info.masterKeyId, refreshed.masterKeyId)
            }
        } finally {
            pass.fill('\u0000')
        }
    }

    @Test
    fun certify_revokeSoft_markRevoked() = runBlocking {
        val certifierPass = "cert-pass".toCharArray()
        val targetPass = "target-pass".toCharArray()
        try {
            val certifier = KeyGenerator().generateKeyRing(
                GenerateKeyRequest("Cert <c@example.com>", certifierPass, KeyAlgorithmType.RSA, 3072),
            )
            val target = KeyGenerator().generateKeyRing(
                GenerateKeyRequest("Target <t@example.com>", targetPass, KeyAlgorithmType.RSA, 3072),
            )
            val certifierInfo = repository.importGeneratedKeyRing(
                certifier.publicArmored,
                certifier.secretArmored,
                "RSA",
            )
            val targetInfo = repository.importKeyRing(target.publicArmored, secret = false)

            repository.certifyKey(
                certifierInfo.masterKeyId,
                targetInfo.masterKeyId,
                certifierPass,
                "Target <t@example.com>",
            )
            val certified = repository.getArmoredPublic(targetInfo.masterKeyId)!!
            assertTrue(String(certified, Charsets.UTF_8).contains("BEGIN PGP PUBLIC"))

            repository.revokeKey(targetInfo.masterKeyId)
            val row = database.keyRingDao().getById(targetInfo.masterKeyId)!!
            assertTrue(row.isRevoked)
        } finally {
            certifierPass.fill('\u0000')
            targetPass.fill('\u0000')
        }
    }

    @Test
    fun applyRevocationCert_marksRevoked() = runBlocking {
        val pass = "apply-rev-pass".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest("ApplyRev <ar@example.com>", pass, KeyAlgorithmType.RSA, 2048),
            )
            val info = repository.importGeneratedKeyRing(
                generated.publicArmored,
                generated.secretArmored,
                "RSA 2048",
            )
            val cert = repository.generateRevocationCert(info.masterKeyId, pass, "compromised")
            val secret = repository.getArmoredSecret(info.masterKeyId)!!
            val revokedSecret = RevocationCertApplier().applyToSecretKeyRing(secret, cert)
            repository.replaceSecretKeyRing(
                info.masterKeyId,
                revokedSecret,
                RevocationCertApplier().applyToPublicKeyRing(generated.publicArmored, cert),
            )
            val row = database.keyRingDao().getById(info.masterKeyId)!!
            assertTrue(row.isRevoked)
        } finally {
            pass.fill('\u0000')
        }
    }

    @Test
    fun generateRevocationCert_nonEmpty() = runBlocking {
        val pass = "rev-cert-pass".toCharArray()
        try {
            val generated = KeyGenerator().generateKeyRing(
                GenerateKeyRequest("RevCert <rc@example.com>", pass, KeyAlgorithmType.RSA, 3072),
            )
            val info = repository.importGeneratedKeyRing(
                generated.publicArmored,
                generated.secretArmored,
                "RSA",
            )
            val cert = repository.generateRevocationCert(info.masterKeyId, pass, "retired")
            val text = String(cert, Charsets.UTF_8)
            assertTrue(text.contains("BEGIN PGP SIGNATURE"))
        } finally {
            pass.fill('\u0000')
        }
    }
}
