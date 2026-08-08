package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP message encryption.
 *
 * Supports public-key and/or passphrase (PBE) recipients, optional ZIP/ZLIB/BZIP2
 * compression, MDC or SEIPDv2 AEAD integrity, and optional one-pass signing.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Date
import kotlinx.coroutines.runBlocking
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.S2K
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBEKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator

/**
 * Parameters for encrypting a message to OpenPGP recipients.
 *
 * At least one of [recipientKeyRings] or [passphrase] must be provided.
 */
data class EncryptRequest(
    val plaintext: ByteArray,
    val recipientKeyRings: List<ByteArray> = emptyList(),
    val asciiArmor: Boolean = true,
    val fileName: String = PGPLiteralData.CONSOLE,
    val integrity: MessageIntegrity = MessageIntegrity.SEIPD_V2_AEAD,
    /**
     * When `false` and [integrity] is [MessageIntegrity.SEIPD_V2_AEAD], degrade to MDC
     * unless every public recipient advertises Features SEIPDv2.
     */
    val forceIntegrity: Boolean = false,
    val aeadAlgorithm: Int = PgpAlgorithmPolicy.defaultAeadAlgorithm,
    val compression: MessageCompression = MessageCompression.NONE,
    val passphrase: CharArray? = null,
    val signSecretRingArmored: ByteArray? = null,
    val signPassphrase: CharArray? = null,
)

/** One plaintext entry for [PgpEncryptor.encryptMany]. */
data class EncryptPlaintext(
    val plaintext: ByteArray,
    val fileName: String = PGPLiteralData.CONSOLE,
    val asciiArmor: Boolean = false,
)

/** Encrypted (and optionally armored) OpenPGP message bytes. */
data class EncryptResult(
    val ciphertext: ByteArray,
)

/** Encrypts data to OpenPGP public-key and/or passphrase recipients. */
class PgpEncryptor {
    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    fun encrypt(request: EncryptRequest): EncryptResult =
        runBlocking { encryptSuspending(request) }

    suspend fun encryptSuspending(request: EncryptRequest): EncryptResult {
        CryptoProgress.stage(CryptoStage.PARSE_KEYS)
        val keys = if (request.recipientKeyRings.isEmpty()) {
            emptyList()
        } else {
            resolveRecipientKeys(request.recipientKeyRings)
        }
        require(keys.isNotEmpty() || request.passphrase != null) {
            "No encryption-capable recipient keys or passphrase"
        }
        val integrity = PgpRecipientCapabilities.resolveIntegrity(
            requested = request.integrity,
            recipientRings = request.recipientKeyRings,
            force = request.forceIntegrity,
        )
        return encryptWithKeys(
            plaintext = request.plaintext,
            recipientKeys = keys,
            asciiArmor = request.asciiArmor,
            fileName = request.fileName,
            integrity = integrity,
            aeadAlgorithm = request.aeadAlgorithm,
            compression = request.compression,
            passphrase = request.passphrase,
            signSecretRingArmored = request.signSecretRingArmored,
            signPassphrase = request.signPassphrase,
        )
    }

    suspend fun encryptMany(
        plaintexts: List<EncryptPlaintext>,
        recipientKeyRings: List<ByteArray>,
        parallelism: Int = 4,
        integrity: MessageIntegrity = MessageIntegrity.SEIPD_V2_AEAD,
        compression: MessageCompression = MessageCompression.NONE,
    ): List<EncryptResult> {
        if (plaintexts.isEmpty()) return emptyList()
        CryptoProgress.stage(CryptoStage.PARSE_KEYS)
        val keys = resolveRecipientKeys(recipientKeyRings)
        val resolvedIntegrity = PgpRecipientCapabilities.resolveIntegrity(
            requested = integrity,
            recipientRings = recipientKeyRings,
            force = false,
        )
        CryptoProgress.stage(CryptoStage.ENCRYPT_SESSION)
        return BcParallel.map(plaintexts, parallelism) { item ->
            encryptWithKeys(
                plaintext = item.plaintext,
                recipientKeys = keys,
                asciiArmor = item.asciiArmor,
                fileName = item.fileName,
                integrity = resolvedIntegrity,
                aeadAlgorithm = PgpAlgorithmPolicy.defaultAeadAlgorithm,
                compression = compression,
                passphrase = null,
                signSecretRingArmored = null,
                signPassphrase = null,
            )
        }
    }

    private suspend fun resolveRecipientKeys(recipientKeyRings: List<ByteArray>): List<PGPPublicKey> {
        val recipientKeys = if (recipientKeyRings.size <= 1) {
            recipientKeyRings.flatMap { extractEncryptionKeys(it) }
        } else {
            BcParallel.map(recipientKeyRings) { extractEncryptionKeys(it) }.flatten()
        }
        val distinct = recipientKeys.distinctBy { it.keyID }
        require(distinct.isNotEmpty()) { "No encryption-capable recipient keys" }
        return distinct
    }

    private fun encryptWithKeys(
        plaintext: ByteArray,
        recipientKeys: List<PGPPublicKey>,
        asciiArmor: Boolean,
        fileName: String,
        integrity: MessageIntegrity,
        aeadAlgorithm: Int,
        compression: MessageCompression,
        passphrase: CharArray?,
        signSecretRingArmored: ByteArray?,
        signPassphrase: CharArray?,
    ): EncryptResult {
        CryptoProgress.stage(CryptoStage.BUILD_LITERAL)
        val innerBytes = if (signSecretRingArmored != null && signPassphrase != null) {
            buildSignedLiteral(plaintext, fileName, signSecretRingArmored, signPassphrase)
        } else {
            buildLiteral(plaintext, fileName)
        }

        val toEncrypt = if (compression == MessageCompression.NONE) {
            innerBytes
        } else {
            ByteArrayOutputStream().use { compressedOut ->
                val gen = PGPCompressedDataGenerator(compression.tag)
                gen.open(compressedOut).use { stream -> stream.write(innerBytes) }
                gen.close()
                compressedOut.toByteArray()
            }
        }

        CryptoProgress.stage(CryptoStage.ENCRYPT_SESSION)
        val encryptorBuilder = BcPGPDataEncryptorBuilder(PgpAlgorithmPolicy.defaultSymmetricAlgorithm)
            .setSecureRandom(SecureRandomProvider.secureRandom)
        when (integrity) {
            MessageIntegrity.MDC -> encryptorBuilder.setWithIntegrityPacket(true)
            MessageIntegrity.SEIPD_V2_AEAD -> encryptorBuilder
                .setWithAEAD(aeadAlgorithm, AEAD_CHUNK_SIZE)
                .setUseV6AEAD()
            MessageIntegrity.LIBREPGP_V5_AEAD -> encryptorBuilder
                .setWithAEAD(aeadAlgorithm, AEAD_CHUNK_SIZE)
                .setUseV5AEAD()
        }
        val encryptedGen = PGPEncryptedDataGenerator(encryptorBuilder)

        for (key in recipientKeys) {
            // BC selects PKESKv3 vs PKESKv6 from the recipient public-key version
            // when generating against an AEAD (v6) data encryptor builder.
            encryptedGen.addMethod(keyEncryptionGenerator(key))
        }
        if (passphrase != null) {
            encryptedGen.addMethod(
                BcPBEKeyEncryptionMethodGenerator(
                    passphrase,
                    S2K.Argon2Params.memoryConstrainedParameters(),
                ).setSecureRandom(SecureRandomProvider.secureRandom),
            )
        }

        val payload = ByteArrayOutputStream().use { encOut ->
            val encStream = encryptedGen.open(encOut, toEncrypt.size.toLong())
            encStream.write(toEncrypt)
            encStream.close()
            encOut.toByteArray()
        }

        val result = if (asciiArmor) {
            CryptoProgress.stage(CryptoStage.ARMOR)
            ByteArrayOutputStream().use { armoredOut ->
                ArmoredOutputStream(armoredOut).use { armor -> armor.write(payload) }
                armoredOut.toByteArray()
            }
        } else {
            payload
        }

        return EncryptResult(ciphertext = result)
    }

    private fun buildLiteral(plaintext: ByteArray, fileName: String): ByteArray =
        ByteArrayOutputStream().use { literalOut ->
            val literalGen = PGPLiteralDataGenerator()
            val literalStream = literalGen.open(
                literalOut,
                PGPLiteralData.BINARY,
                fileName,
                plaintext.size.toLong(),
                Date(),
            )
            literalStream.write(plaintext)
            literalStream.close()
            literalGen.close()
            literalOut.toByteArray()
        }

    /** One-pass signature + literal + signature packet chain. */
    private fun buildSignedLiteral(
        plaintext: ByteArray,
        fileName: String,
        secretRingArmored: ByteArray,
        passphrase: CharArray,
    ): ByteArray {
        val secretRing = PGPUtil.getDecoderStream(ByteArrayInputStream(secretRingArmored)).use { input ->
            PGPObjectFactory(input, PgpFingerprints.calculator).nextObject() as PGPSecretKeyRing
        }
        val signingKey = findSigningSecretKey(secretRing)
        val useBc = PgpOperators.useBcForPublicKey(signingKey.publicKey)
        val privateKey = PgpOperators.extractPrivateKey(signingKey, passphrase)
        val sigGen = PGPSignatureGenerator(PgpOperators.contentSignerBuilder(signingKey.publicKey, useBc))
        sigGen.init(PGPSignature.BINARY_DOCUMENT, privateKey)

        return ByteArrayOutputStream().use { out ->
            sigGen.generateOnePassVersion(false).encode(out)
            val literalGen = PGPLiteralDataGenerator()
            literalGen.open(
                out,
                PGPLiteralData.BINARY,
                fileName,
                plaintext.size.toLong(),
                Date(),
            ).use { literalStream ->
                literalStream.write(plaintext)
                sigGen.update(plaintext)
            }
            literalGen.close()
            sigGen.generate().encode(out)
            out.toByteArray()
        }
    }

    private fun findSigningSecretKey(ring: PGPSecretKeyRing): PGPSecretKey {
        val iter = ring.secretKeys
        while (iter.hasNext()) {
            val sk = iter.next()
            if (sk.isSigningKey) return sk
        }
        return ring.secretKey
    }

    private fun keyEncryptionGenerator(key: PGPPublicKey): PublicKeyKeyEncryptionMethodGenerator =
        if (key.algorithm in BC_PKE_ALGORITHMS) {
            BcPublicKeyKeyEncryptionMethodGenerator(key)
        } else {
            JcePublicKeyKeyEncryptionMethodGenerator(key)
        }

    companion object {
        /** BC AEAD chunk size exponent (2^(n+6) bytes). */
        private const val AEAD_CHUNK_SIZE = 6

        private val BC_PKE_ALGORITHMS = setOf(
            PGPPublicKey.ECDH,
            PGPPublicKey.ECDSA,
            PGPPublicKey.EC,
            PublicKeyAlgorithmTags.X25519,
            PublicKeyAlgorithmTags.X448,
        )
    }

    private fun extractEncryptionKeys(armored: ByteArray): List<PGPPublicKey> {
        val keys = ArrayList<PGPPublicKey>()
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            when (val obj = PGPObjectFactory(input, PgpFingerprints.calculator).nextObject()) {
                is PGPPublicKeyRing -> {
                    val iter = obj.publicKeys
                    while (iter.hasNext()) {
                        val key = iter.next()
                        if (key.isEncryptionKey) keys.add(key)
                    }
                    if (keys.isEmpty()) keys.add(obj.publicKey)
                }
                is PGPSecretKeyRing -> {
                    val iter = obj.secretKeys
                    while (iter.hasNext()) {
                        val key = iter.next().publicKey
                        if (key.isEncryptionKey) keys.add(key)
                    }
                    if (keys.isEmpty()) keys.add(obj.publicKey)
                }
                else -> throw PgpException("Unsupported key ring type: ${obj?.javaClass?.simpleName}")
            }
        }
        return keys
    }
}
