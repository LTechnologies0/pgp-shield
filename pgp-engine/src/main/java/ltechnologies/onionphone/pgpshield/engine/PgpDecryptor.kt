package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP message decryption.
 *
 * Unlocks recipient secret keys or PBE passphrases, decrypts encrypted data
 * packets (MDC or AEAD), optionally verifies embedded one-pass signatures, and
 * fails closed on integrity errors.
 */

import java.io.ByteArrayInputStream
import java.io.InputStream
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPOnePassSignature
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPBEEncryptedData
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder
import java.nio.ByteBuffer

/**
 * Parameters for decrypting an OpenPGP message.
 *
 * Provide [secretKeyRingArmored] for PKESK messages and/or [passphrase] for
 * SKESK (PBE) messages. [signerPublicKeyRingsArmored] is used to verify
 * embedded one-pass signatures when present.
 */
data class DecryptRequest(
    val ciphertext: ByteArray,
    val secretKeyRingArmored: ByteArray? = null,
    val passphrase: CharArray,
    val signerPublicKeyRingsArmored: List<ByteArray> = emptyList(),
    /** Optional hardware token for divert-to-card secret keys. */
    val smartCard: SmartCardPort? = null,
    /**
     * Cached clear session key from a prior [DecryptResult] (OpenPGP API
     * `EXTRA_DECRYPTION_RESULT`). When set, PKESK unlock skips the passphrase.
     * Wire format: first byte = symmetric algorithm tag, remainder = key bytes.
     */
    val cachedDecryptedSessionKey: ByteArray? = null,
)

/**
 * Result of a successful decryption.
 *
 * @property plaintext Literal data payload bytes.
 * @property fileName Filename from the literal data packet, if any.
 * @property verified Integrity check passed (`true` on success).
 * @property signatureValid Embedded signature verified, or `null` if none.
 * @property signerKeyId Key ID of an embedded signature, if any.
 * @property securityProblems Always empty on success (kept for API stability).
 * @property sessionKey Opaque encrypted-session marker for API caching (key id bytes).
 * @property decryptedSessionKey Clear session key (`algo` + key material) for API reuse.
 */
data class DecryptResult(
    val plaintext: ByteArray,
    val fileName: String?,
    val verified: Boolean,
    val signatureValid: Boolean? = null,
    val signerKeyId: Long? = null,
    val securityProblems: List<SecurityProblem> = emptyList(),
    val sessionKey: ByteArray? = null,
    val decryptedSessionKey: ByteArray? = null,
    /** Literal packet modification time (ms since epoch), or `0` if unknown. */
    val modificationTimeMs: Long = 0L,
    /** Guessed MIME from literal format (`t`/`u` → text/plain, else octet-stream). */
    val mimeType: String? = null,
    /** Embedded signature creation time (ms), when present. */
    val signatureTimestampMs: Long? = null,
)

/** Decrypts OpenPGP messages and validates integrity protection. */
class PgpDecryptor {
    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Decrypts [request.ciphertext].
     *
     * @throws PgpException if no matching key, wrong passphrase, integrity failure, or parse failure.
     */
    fun decrypt(request: DecryptRequest): DecryptResult {
        CryptoProgress.stage(CryptoStage.PARSE_KEYS)
        val secretRing = request.secretKeyRingArmored?.let { armored ->
            PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
                PGPObjectFactory(input, PgpFingerprints.calculator).nextObject() as PGPSecretKeyRing
            }
        }

        CryptoProgress.stage(CryptoStage.PARSE_KEYS)
        val encryptedList = PgpStreams.readEncryptedList(request.ciphertext, PgpFingerprints.calculator)

        var integritySource: org.bouncycastle.openpgp.PGPEncryptedData? = null
        var clearFactory: PGPObjectFactory? = null
        var lastError: Exception? = null
        var sawChecksumMismatch = false
        var sessionKeyOut: ByteArray? = null
        var decryptedSessionKeyOut: ByteArray? = null

        val cachedSession = parseCachedSessionKey(request.cachedDecryptedSessionKey)

        val pbeIter = encryptedList.encryptedDataObjects
        while (pbeIter.hasNext()) {
            when (val packet = pbeIter.next()) {
                is PGPPublicKeyEncryptedData -> {
                    try {
                        if (cachedSession != null) {
                            CryptoProgress.stage(CryptoStage.DECRYPT_PAYLOAD)
                            val skFactory = BcSessionKeyDataDecryptorFactory(cachedSession)
                            PgpAlgorithmPolicy.requireAllowedSymmetric(cachedSession.algorithm)
                            val clearStream = packet.getDataStream(skFactory)
                            integritySource = packet
                            clearFactory = PGPObjectFactory(clearStream, PgpFingerprints.calculator)
                            sessionKeyOut = keyIdMarker(packet.keyID)
                            decryptedSessionKeyOut = encodeSessionKey(cachedSession)
                            break
                        }
                        val ring = secretRing ?: continue
                        val secretKey = ring.getSecretKey(packet.keyID) ?: continue
                        CryptoProgress.stage(CryptoStage.UNLOCK_SECRET)
                        val (clearStream, factory) = if (
                            secretKey.isPrivateKeyEmpty ||
                            request.smartCard?.ownsKey(packet.keyID) == true
                        ) {
                            val card = request.smartCard
                                ?: throw PgpException("Secret key is on smart card but no card session")
                            val skFactory = SmartCardPublicKeyDataDecryptorFactory(card, packet.keyID)
                            PgpAlgorithmPolicy.requireAllowedSymmetric(packet.getSymmetricAlgorithm(skFactory))
                            packet.getDataStream(skFactory) to skFactory
                        } else {
                            val privateKey = PgpOperators.extractPrivateKey(secretKey, request.passphrase)
                            CryptoProgress.stage(CryptoStage.DECRYPT_PAYLOAD)
                            decryptPkStreamWithFactory(packet, privateKey)
                        }
                        CryptoProgress.stage(CryptoStage.DECRYPT_PAYLOAD)
                        integritySource = packet
                        clearFactory = PGPObjectFactory(clearStream, PgpFingerprints.calculator)
                        runCatching {
                            val sk = packet.getSessionKey(factory)
                            sessionKeyOut = keyIdMarker(packet.keyID)
                            decryptedSessionKeyOut = encodeSessionKey(sk)
                        }
                        break
                    } catch (e: Exception) {
                        if (e is PgpException && e.securityProblem == SecurityProblem.INSECURE_ALGORITHM) {
                            throw e
                        }
                        if (PgpOperators.isPassphraseChecksumMismatch(e)) {
                            sawChecksumMismatch = true
                        }
                        lastError = e
                    }
                }
                is PGPPBEEncryptedData -> {
                    if (cachedSession != null) continue
                    try {
                        CryptoProgress.stage(CryptoStage.UNLOCK_SECRET)
                        val factory = BcPBEDataDecryptorFactory(
                            request.passphrase,
                            JcaPlatform.digestCalculators,
                        )
                        CryptoProgress.stage(CryptoStage.DECRYPT_PAYLOAD)
                        PgpAlgorithmPolicy.requireAllowedSymmetric(packet.getSymmetricAlgorithm(factory))
                        val clearStream = packet.getDataStream(factory)
                        integritySource = packet
                        clearFactory = PGPObjectFactory(clearStream, PgpFingerprints.calculator)
                        break
                    } catch (e: Exception) {
                        if (e is PgpException && e.securityProblem == SecurityProblem.INSECURE_ALGORITHM) {
                            throw e
                        }
                        lastError = e
                    }
                }
            }
        }

        val enc = integritySource ?: throw PgpException(
            when {
                sawChecksumMismatch -> "Wrong passphrase"
                else -> humanizeUnlockError(lastError)
            },
            cause = lastError,
        )
        val plainFactory = clearFactory ?: throw PgpException("Decryption failed")


        val signerKeys = buildSignerKeyLookup(request, secretRing)
        val result = parseInnerMessage(plainFactory, signerKeys)

        CryptoProgress.stage(CryptoStage.VERIFY_MDC)
        verifyIntegrity(enc)
        return result.copy(
            sessionKey = sessionKeyOut,
            decryptedSessionKey = decryptedSessionKeyOut,
        )
    }

    private fun verifyIntegrity(enc: org.bouncycastle.openpgp.PGPEncryptedData) {
        if (enc.isAEAD) {
            // SEIPDv2 (SymmetricEncIntegrityPacket v2): BC verify() works.
            // LibrePGP AEADEncDataPacket (tag 20): AEAD auth already enforced while
            // draining the cleartext stream; BC.verify() wrongly requires SEIP.
            if (enc.isIntegrityProtected && !enc.verify()) {
                throw PgpException("Message integrity check failed (AEAD)", SecurityProblem.MDC_FAILURE)
            }
            return
        }
        if (!enc.isIntegrityProtected) {
            throw PgpException(
                "Message lacks integrity protection (no MDC)",
                SecurityProblem.UNSIGNED,
            )
        }
        if (!enc.verify()) {
            throw PgpException(
                "Message integrity check failed (MDC)",
                SecurityProblem.MDC_FAILURE,
            )
        }
    }

    private fun parseInnerMessage(
        factory: PGPObjectFactory,
        signerKeys: (Long) -> PGPPublicKey?,
    ): DecryptResult {
        var message = factory.nextObject()
        if (message is PGPCompressedData) {
            PgpAlgorithmPolicy.requireAllowedCompression(message.algorithm)
            message = PGPObjectFactory(message.dataStream, PgpFingerprints.calculator).nextObject()
        }

        if (message is PGPOnePassSignatureList) {
            return parseOnePassSigned(message, factory, signerKeys)
        }

        val literal = message as? PGPLiteralData
            ?: throw PgpException("Unexpected packet after decrypt: ${message?.javaClass?.simpleName}")
        val plaintext = literal.inputStream.use { PgpIo.readLimited(it) }
        return DecryptResult(
            plaintext = plaintext,
            fileName = literal.fileName,
            verified = true,
            modificationTimeMs = literal.modificationTime?.time ?: 0L,
            mimeType = mimeTypeForLiteral(literal),
        )
    }

    private fun parseOnePassSigned(
        opsList: PGPOnePassSignatureList,
        factory: PGPObjectFactory,
        signerKeys: (Long) -> PGPPublicKey?,
    ): DecryptResult {
        val ops = opsList[0] as PGPOnePassSignature
        val key = signerKeys(ops.keyID)
        if (key != null) {
            CryptoProgress.stage(CryptoStage.VERIFY_SIGNATURE)
            PgpAlgorithmPolicy.requireAllowedHash(ops.hashAlgorithm)
            PgpAlgorithmPolicy.requireHashStrengthForKey(key, ops.hashAlgorithm)
            val useBc = PgpOperators.useBcForPublicKey(key)
            try {
                ops.init(PgpOperators.contentVerifierProvider(useBc), key)
            } catch (e: PgpException) {
                throw e
            } catch (_: Exception) {
                ops.init(PgpOperators.contentVerifierProvider(!useBc), key)
            }
        }

        var next = factory.nextObject()
        if (next is PGPCompressedData) {
            PgpAlgorithmPolicy.requireAllowedCompression(next.algorithm)
            next = PGPObjectFactory(next.dataStream, PgpFingerprints.calculator).nextObject()
        }
        val literal = next as? PGPLiteralData
            ?: throw PgpException("Expected literal after one-pass signature")
        val plaintext = literal.inputStream.use { input ->
            val bytes = PgpIo.readLimited(input)
            if (key != null) {
                ops.update(bytes)
            }
            bytes
        }
        val sigList = factory.nextObject() as? PGPSignatureList
            ?: throw PgpException("Missing signature after one-pass literal")
        val sig = sigList[0] as PGPSignature
        if (key != null) {
            PgpAlgorithmPolicy.requireAllowedHash(sig.hashAlgorithm)
            PgpAlgorithmPolicy.requireHashStrengthForKey(key, sig.hashAlgorithm)
        }

        val signatureValid = if (key != null) {
            try {
                ops.verify(sig)
            } catch (_: Exception) {
                false
            }
        } else {
            false
        }

        return DecryptResult(
            plaintext = plaintext,
            fileName = literal.fileName,
            verified = true,
            signatureValid = signatureValid,
            signerKeyId = ops.keyID,
            modificationTimeMs = literal.modificationTime?.time ?: 0L,
            mimeType = mimeTypeForLiteral(literal),
            signatureTimestampMs = sig.creationTime?.time,
        )
    }

    private fun mimeTypeForLiteral(literal: PGPLiteralData): String =
        when (literal.format) {
            PGPLiteralData.TEXT.code, PGPLiteralData.UTF8.code -> "text/plain"
            else -> "application/octet-stream"
        }

    private fun buildSignerKeyLookup(
        request: DecryptRequest,
        secretRing: PGPSecretKeyRing?,
    ): (Long) -> PGPPublicKey? {
        val rings = ArrayList<PGPPublicKeyRing>()
        for (armored in request.signerPublicKeyRingsArmored) {
            readPublicRing(armored)?.let { rings.add(it) }
        }
        if (secretRing != null) {
            // Secret ring public keys can verify self-signed messages.
            val pubs = ArrayList<PGPPublicKey>()
            val iter = secretRing.publicKeys
            while (iter.hasNext()) pubs.add(iter.next())
            return { keyId ->
                secretRing.getPublicKey(keyId)
                    ?: rings.firstNotNullOfOrNull { it.getPublicKey(keyId) }
            }
        }
        return { keyId -> rings.firstNotNullOfOrNull { it.getPublicKey(keyId) } }
    }

    private fun readPublicRing(armored: ByteArray): PGPPublicKeyRing? =
        try {
            PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
                PGPObjectFactory(input, PgpFingerprints.calculator).nextObject() as? PGPPublicKeyRing
            }
        } catch (_: Exception) {
            null
        }

    private fun decryptPkStream(pbe: PGPPublicKeyEncryptedData, privateKey: PGPPrivateKey): InputStream =
        decryptPkStreamWithFactory(pbe, privateKey).first

    private fun decryptPkStreamWithFactory(
        pbe: PGPPublicKeyEncryptedData,
        privateKey: PGPPrivateKey,
    ): Pair<InputStream, org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory> {
        fun open(factory: org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory):
            Pair<InputStream, org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory> {
            PgpAlgorithmPolicy.requireAllowedSymmetric(pbe.getSymmetricAlgorithm(factory))
            return pbe.getDataStream(factory) to factory
        }
        return try {
            open(BcPublicKeyDataDecryptorFactory(privateKey))
        } catch (e: PgpException) {
            throw e
        } catch (_: Exception) {
            open(JcePublicKeyDataDecryptorFactoryBuilder().build(privateKey))
        }
    }

    companion object {
        internal fun humanizeUnlockError(error: Exception?): String {
            if (error != null && PgpOperators.isPassphraseChecksumMismatch(error)) {
                return "Wrong passphrase"
            }
            val msg = error?.message.orEmpty()
            return msg.ifBlank { "No matching secret key or wrong passphrase for ciphertext" }
        }

        internal fun encodeSessionKey(sessionKey: PGPSessionKey): ByteArray =
            byteArrayOf(sessionKey.algorithm.toByte()) + sessionKey.key

        internal fun parseCachedSessionKey(encoded: ByteArray?): PGPSessionKey? {
            if (encoded == null || encoded.size < 2) return null
            val algo = encoded[0].toInt() and 0xff
            val key = encoded.copyOfRange(1, encoded.size)
            return PGPSessionKey(algo, key)
        }

        internal fun keyIdMarker(keyId: Long): ByteArray =
            ByteBuffer.allocate(8).putLong(keyId).array()
    }
}
