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
import org.bouncycastle.openpgp.operator.bc.BcPBEDataDecryptorFactory
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder

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
 */
data class DecryptResult(
    val plaintext: ByteArray,
    val fileName: String?,
    val verified: Boolean,
    val signatureValid: Boolean? = null,
    val signerKeyId: Long? = null,
    val securityProblems: List<SecurityProblem> = emptyList(),
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

        val pbeIter = encryptedList.encryptedDataObjects
        while (pbeIter.hasNext()) {
            when (val packet = pbeIter.next()) {
                is PGPPublicKeyEncryptedData -> {
                    val ring = secretRing ?: continue
                    val secretKey = ring.getSecretKey(packet.keyID) ?: continue
                    try {
                        CryptoProgress.stage(CryptoStage.UNLOCK_SECRET)
                        val clearStream = if (
                            secretKey.isPrivateKeyEmpty ||
                            request.smartCard?.ownsKey(packet.keyID) == true
                        ) {
                            val card = request.smartCard
                                ?: throw PgpException("Secret key is on smart card but no card session")
                            val factory = SmartCardPublicKeyDataDecryptorFactory(card, packet.keyID)
                            PgpAlgorithmPolicy.requireAllowedSymmetric(packet.getSymmetricAlgorithm(factory))
                            packet.getDataStream(factory)
                        } else {
                            val privateKey = PgpOperators.extractPrivateKey(secretKey, request.passphrase)
                            CryptoProgress.stage(CryptoStage.DECRYPT_PAYLOAD)
                            decryptPkStream(packet, privateKey)
                        }
                        CryptoProgress.stage(CryptoStage.DECRYPT_PAYLOAD)
                        integritySource = packet
                        clearFactory = PGPObjectFactory(clearStream, PgpFingerprints.calculator)
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
        return result
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
        )
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

    private fun decryptPkStream(pbe: PGPPublicKeyEncryptedData, privateKey: PGPPrivateKey): InputStream {
        fun open(factory: org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory): InputStream {
            PgpAlgorithmPolicy.requireAllowedSymmetric(pbe.getSymmetricAlgorithm(factory))
            return pbe.getDataStream(factory)
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
    }
}
