package ltechnologies.onionphone.pgpshield.data

import ltechnologies.onionphone.pgpshield.data.db.AppDatabase
import ltechnologies.onionphone.pgpshield.data.db.KeyRingEntity
import ltechnologies.onionphone.pgpshield.data.db.UserIdEntity
import ltechnologies.onionphone.pgpshield.data.security.HardwarePassphraseVault
import ltechnologies.onionphone.pgpshield.data.vault.KeyBlobStore
import ltechnologies.onionphone.pgpshield.engine.AlgorithmLabels
import ltechnologies.onionphone.pgpshield.engine.KeyRingExporter
import ltechnologies.onionphone.pgpshield.engine.KeyRingReader
import ltechnologies.onionphone.pgpshield.engine.PgpAlgorithmPolicy
import ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flowOn

/**
 * Default [KeyRepository] implementation coordinating Room, [KeyBlobStore], and the PGP engine.
 *
 * Validates imported keys against [PgpAlgorithmPolicy], persists metadata and encrypted blobs,
 * and performs keyserver refresh, certification, and uid management operations.
 */
@Singleton
class KeyRepositoryImpl @Inject constructor(
    private val database: AppDatabase,
    private val blobStore: KeyBlobStore,
    private val keyserverClient: KeyserverClient,
    private val hardwarePassphraseVault: HardwarePassphraseVault,
) : KeyRepository {
    private val reader = KeyRingReader()

    /** @see KeyRepository.observeKeys */
    override fun observeKeys(): Flow<List<KeySummary>> =
        combine(
            database.keyRingDao().observeAll(),
            database.userIdDao().observeAll(),
        ) { rings, allUserIds ->
            val userIdsByKey = allUserIds.groupBy { it.masterKeyId }
            rings.map { ring ->
                val userIds = userIdsByKey[ring.masterKeyId].orEmpty()
                ring.toSummary(userIds)
            }
        }.flowOn(Dispatchers.IO)

    /** @see KeyRepository.importKeyRing */
    override suspend fun importKeyRing(armored: ByteArray, secret: Boolean): KeyRingInfo {
        ImportGuard.checkSize(armored)
        val info = readAndValidate(armored, secret)
        val (path, publicPath) = coroutineScope {
            val secretDef = async(Dispatchers.IO) { blobStore.write(info.masterKeyId, armored) }
            val publicDef = if (secret) {
                async(Dispatchers.IO) {
                    blobStore.writePublic(info.masterKeyId, KeyRingExporter.publicArmoredFromSecret(armored))
                }
            } else {
                null
            }
            secretDef.await() to publicDef?.await()
        }
        persist(info, path, publicPath, secret, algorithmLabel(info))
        return info
    }

    /** @see KeyRepository.importGeneratedKeyRing */
    override suspend fun importGeneratedKeyRing(
        publicArmored: ByteArray,
        secretArmored: ByteArray,
        primaryAlgorithm: String,
        hardwareManagedPassphrase: Boolean,
    ): KeyRingInfo {
        ImportGuard.checkSize(secretArmored)
        val info = readAndValidate(secretArmored, secret = true)
        val (secretPath, publicPath) = coroutineScope {
            val s = async(Dispatchers.IO) { blobStore.write(info.masterKeyId, secretArmored) }
            val p = async(Dispatchers.IO) { blobStore.writePublic(info.masterKeyId, publicArmored) }
            s.await() to p.await()
        }
        persist(
            info,
            secretPath,
            publicPath,
            secret = true,
            primaryAlgorithm,
            hardwareManagedPassphrase = hardwareManagedPassphrase,
        )
        return info
    }

    /** @see KeyRepository.getKeyDetail */
    override suspend fun getKeyDetail(keyId: Long): KeyDetail? {
        val entity = database.keyRingDao().getById(keyId) ?: return null
        val armored = try {
            if (!blobStore.ensureBlobPresent(entity.blobPath)) {
                throw java.io.FileNotFoundException(entity.blobPath)
            }
            blobStore.read(entity.blobPath)
        } catch (_: java.io.FileNotFoundException) {
            // Blob truly gone — drop orphan Room metadata only.
            database.userIdDao().deleteForKey(keyId)
            database.keyRingDao().delete(keyId)
            return null
        }
        // Crypto / app-lock failures must NOT delete key metadata (would destroy recoverability).
        val info = if (entity.isSecret) {
            reader.readSecretKeyRing(armored.inputStream())
        } else {
            reader.readPublicKeyRing(armored.inputStream())
        }
        return KeyDetail(
            summary = entity.toSummary(database.userIdDao().forKey(keyId)),
            subkeys = info.subkeys,
        )
    }

    /** @see KeyRepository.exportKeyRing */
    override suspend fun exportKeyRing(keyId: Long): ByteArray {
        val entity = database.keyRingDao().getById(keyId)
            ?: throw IllegalArgumentException("Unknown key $keyId")
        return blobStore.read(entity.blobPath)
    }

    /** @see KeyRepository.revokeKey */
    override suspend fun revokeKey(keyId: Long) {
        database.keyRingDao().markRevoked(keyId)
    }

    /** @see KeyRepository.deleteKey */
    override suspend fun deleteKey(keyId: Long) {
        val entity = database.keyRingDao().getById(keyId)
            ?: throw IllegalStateException("Key not found: 0x${keyId.toULong().toString(16).uppercase()}")
        blobStore.delete(entity.blobPath)
        entity.publicBlobPath?.let { blobStore.delete(it) }
        hardwarePassphraseVault.deletePassphrase(keyId)
        database.userIdDao().deleteForKey(keyId)
        database.keyRingDao().delete(keyId)
    }

    /** @see KeyRepository.search */
    override suspend fun search(query: String): List<KeySummary> {
        val rings = database.keyRingDao().search(query)
        if (rings.isEmpty()) return emptyList()
        val uidsByKey = database.userIdDao().getAll().groupBy { it.masterKeyId }
        return rings.map { ring -> ring.toSummary(uidsByKey[ring.masterKeyId].orEmpty()) }
    }

    /** @see KeyRepository.getArmoredSecret */
    override suspend fun getArmoredSecret(keyId: Long): ByteArray? {
        val entity = database.keyRingDao().getById(keyId) ?: return null
        if (!entity.isSecret) return null
        if (!blobStore.ensureBlobPresent(entity.blobPath)) return null
        // Propagate lock/crypto failures — do not swallow as "missing key".
        return blobStore.read(entity.blobPath)
    }

    /** @see KeyRepository.getArmoredPublic */
    override suspend fun getArmoredPublic(keyId: Long): ByteArray? {
        val entity = database.keyRingDao().getById(keyId) ?: return null
        entity.publicBlobPath?.let { path ->
            if (!blobStore.ensureBlobPresent(path)) return@let
            return blobStore.read(path)
        }
        if (!blobStore.ensureBlobPresent(entity.blobPath)) return null
        val blob = blobStore.read(entity.blobPath)
        return if (entity.isSecret) {
            KeyRingExporter.publicArmoredFromSecret(blob)
        } else {
            blob
        }
    }

    /** @see KeyRepository.isEncryptRecipientAllowed */
    override suspend fun isEncryptRecipientAllowed(keyId: Long): Boolean {
        val entity = database.keyRingDao().getById(keyId) ?: return false
        if (entity.isRevoked || entity.trustLevel == KeySummary.TRUST_NEVER) return false
        val armored = getArmoredPublic(keyId) ?: return false
        return try {
            // Rejects expired / weak / disallowed algorithms at encrypt time.
            readAndValidate(armored, secret = false, allowRevoked = false)
            true
        } catch (_: Exception) {
            false
        }
    }

    /** @see KeyRepository.changePassphrase */
    override suspend fun changePassphrase(keyId: Long, newSecretArmored: ByteArray) {
        val publicArmored = KeyRingExporter.publicArmoredFromSecret(newSecretArmored)
        replaceSecretKeyRing(keyId, newSecretArmored, publicArmored)
    }

    /** @see KeyRepository.replaceSecretKeyRing */
    override suspend fun replaceSecretKeyRing(keyId: Long, secretArmored: ByteArray, publicArmored: ByteArray) {
        ImportGuard.checkSize(secretArmored)
        val entity = database.keyRingDao().getById(keyId) ?: throw IllegalArgumentException("Unknown key $keyId")
        if (!entity.isSecret) throw IllegalArgumentException("Not a secret key")
        val info = readAndValidate(secretArmored, secret = true, allowRevoked = true)
        val (secretPath, publicPath) = coroutineScope {
            val s = async(Dispatchers.IO) { blobStore.write(entity.masterKeyId, secretArmored) }
            val p = async(Dispatchers.IO) { blobStore.writePublic(entity.masterKeyId, publicArmored) }
            s.await() to p.await()
        }
        val oldSecret = entity.blobPath
        val oldPublic = entity.publicBlobPath
        database.keyRingDao().insert(
            entity.copy(
                blobPath = secretPath,
                publicBlobPath = publicPath,
                subkeyCount = info.subkeys.size,
                isRevoked = info.isRevoked,
            ),
        )
        if (oldSecret != secretPath) runCatching { blobStore.delete(oldSecret) }
        if (oldPublic != null && oldPublic != publicPath) runCatching { blobStore.delete(oldPublic) }
    }

    /** @see KeyRepository.generateRevocationCert */
    override suspend fun generateRevocationCert(
        keyId: Long,
        passphrase: CharArray,
        reasonText: String,
    ): ByteArray {
        val secret = getArmoredSecret(keyId) ?: throw IllegalArgumentException("Secret key not found")
        return ltechnologies.onionphone.pgpshield.engine.RevocationCertGenerator().generate(
            ltechnologies.onionphone.pgpshield.engine.RevocationCertRequest(
                secretKeyRingArmored = secret,
                passphrase = passphrase,
                reasonText = reasonText,
            ),
        )
    }

    /** @see KeyRepository.certifyKey */
    override suspend fun certifyKey(
        certifierKeyId: Long,
        targetKeyId: Long,
        certifierPassphrase: CharArray,
        userId: String,
    ): ByteArray {
        val certifierSecret = getArmoredSecret(certifierKeyId)
            ?: throw IllegalArgumentException("Certifier secret not found")
        val targetPublic = getArmoredPublic(targetKeyId)
            ?: throw IllegalArgumentException("Target public key not found")
        val result = ltechnologies.onionphone.pgpshield.engine.KeyCertifier().certify(
            ltechnologies.onionphone.pgpshield.engine.CertifyKeyRequest(
                certifierSecretArmored = certifierSecret,
                certifierPassphrase = certifierPassphrase,
                targetPublicArmored = targetPublic,
                userId = userId,
            ),
        )
        val entity = database.keyRingDao().getById(targetKeyId)
        if (entity != null) {
            val path = entity.publicBlobPath ?: entity.blobPath
            if (!entity.isSecret) {
                blobStore.write(entity.masterKeyId, result.certifiedPublicArmored)
            } else {
                blobStore.writePublic(entity.masterKeyId, result.certifiedPublicArmored)
            }
        }
        return result.certifiedPublicArmored
    }

    /** @see KeyRepository.refreshKeyFromKeyserver */
    override suspend fun refreshKeyFromKeyserver(keyId: Long, baseUrl: String): KeyRingInfo {
        val entity = database.keyRingDao().getById(keyId)
            ?: throw IllegalArgumentException("Unknown key $keyId")
        val query = entity.fingerprint.replace(" ", "")
        val armored = keyserverClient.fetchKey(baseUrl, query)
        ImportGuard.checkSize(armored)
        val info = readAndValidate(armored, secret = false, allowRevoked = true)
        if (entity.isSecret) {
            if (entity.publicBlobPath != null) {
                blobStore.writePublic(entity.masterKeyId, armored)
            }
        } else {
            blobStore.write(entity.masterKeyId, armored)
        }
        database.keyRingDao().insert(
            entity.copy(
                fingerprint = info.fingerprint,
                isRevoked = info.isRevoked,
                subkeyCount = info.subkeys.size,
            ),
        )
        database.userIdDao().deleteForKey(keyId)
        database.userIdDao().insertAll(
            info.userIds.map {
                UserIdEntity(masterKeyId = keyId, userId = it.userId, isPrimary = it.isPrimary)
            },
        )
        return info
    }

    /** @see KeyRepository.addUserId */
    override suspend fun addUserId(keyId: Long, passphrase: CharArray, userId: String) {
        val entity = database.keyRingDao().getById(keyId)
            ?: throw IllegalArgumentException("Unknown key $keyId")
        if (!entity.isSecret) throw IllegalArgumentException("Not a secret key")
        val secret = blobStore.read(entity.blobPath)
        val updated = ltechnologies.onionphone.pgpshield.engine.UserIdManager().addUserId(
            ltechnologies.onionphone.pgpshield.engine.UserIdEditRequest(
                secretKeyRingArmored = secret,
                passphrase = passphrase,
                userId = userId,
            ),
        )
        val public = KeyRingExporter.publicArmoredFromSecret(updated)
        replaceSecretKeyRing(keyId, updated, public)
        val info = readAndValidate(updated, secret = true)
        database.userIdDao().deleteForKey(keyId)
        database.userIdDao().insertAll(
            info.userIds.map {
                UserIdEntity(masterKeyId = keyId, userId = it.userId, isPrimary = it.isPrimary)
            },
        )
    }

    /** @see KeyRepository.setTrustLevel */
    override suspend fun setTrustLevel(keyId: Long, trustLevel: Int) {
        require(trustLevel in 0..3) { "Trust level must be 0..3" }
        database.keyRingDao().getById(keyId) ?: throw IllegalArgumentException("Unknown key $keyId")
        database.keyRingDao().setTrustLevel(keyId, trustLevel)
    }

    /** @see KeyRepository.uploadPublicKey */
    override suspend fun uploadPublicKey(keyId: Long, baseUrl: String) {
        val public = getArmoredPublic(keyId) ?: throw IllegalArgumentException("Public key not found")
        keyserverClient.uploadPublicKey(baseUrl, public)
    }

    /** @see KeyRepository.purgeMissingBlobKeys */
    override suspend fun purgeMissingBlobKeys(): Int {
        var removed = 0
        for (entity in database.keyRingDao().getAll()) {
            val present = blobStore.ensureBlobPresent(entity.blobPath)
            if (!present) {
                database.userIdDao().deleteForKey(entity.masterKeyId)
                database.keyRingDao().delete(entity.masterKeyId)
                removed++
            }
        }
        return removed
    }

    private fun readAndValidate(armored: ByteArray, secret: Boolean, allowRevoked: Boolean = false): KeyRingInfo {
        val info = if (secret) {
            reader.readSecretKeyRing(armored.inputStream())
        } else {
            reader.readPublicKeyRing(armored.inputStream())
        }
        PgpAlgorithmPolicy.validateKeyRing(info, allowRevoked)
        return info
    }

    private suspend fun persist(
        info: KeyRingInfo,
        blobPath: String,
        publicBlobPath: String?,
        secret: Boolean,
        primaryAlgorithm: String,
        hardwareManagedPassphrase: Boolean = false,
    ) {
        database.keyRingDao().insert(
            KeyRingEntity(
                masterKeyId = info.masterKeyId,
                fingerprint = info.fingerprint,
                isSecret = secret,
                isRevoked = info.isRevoked,
                blobPath = blobPath,
                publicBlobPath = publicBlobPath,
                createdAt = System.currentTimeMillis(),
                primaryAlgorithm = primaryAlgorithm,
                subkeyCount = info.subkeys.size,
                hardwareManagedPassphrase = hardwareManagedPassphrase,
            ),
        )
        database.userIdDao().deleteForKey(info.masterKeyId)
        database.userIdDao().insertAll(
            info.userIds.map {
                UserIdEntity(
                    masterKeyId = info.masterKeyId,
                    userId = it.userId,
                    isPrimary = it.isPrimary,
                )
            },
        )
    }

    private fun algorithmLabel(info: KeyRingInfo): String {
        val master = info.subkeys.firstOrNull { it.keyId == info.masterKeyId }
            ?: info.subkeys.firstOrNull()
            ?: return "Unknown"
        return AlgorithmLabels.forAlgorithm(master.algorithm)
    }

    private fun KeyRingEntity.toSummary(userIds: List<UserIdEntity>): KeySummary =
        KeySummary(
            masterKeyId = masterKeyId,
            fingerprint = fingerprint,
            primaryUserId = userIds.firstOrNull { it.isPrimary }?.userId ?: userIds.firstOrNull()?.userId,
            isSecret = isSecret,
            isRevoked = isRevoked,
            primaryAlgorithm = primaryAlgorithm,
            createdAt = createdAt,
            subkeyCount = subkeyCount,
            trustLevel = trustLevel,
            hardwareManagedPassphrase = hardwareManagedPassphrase,
        )
}
