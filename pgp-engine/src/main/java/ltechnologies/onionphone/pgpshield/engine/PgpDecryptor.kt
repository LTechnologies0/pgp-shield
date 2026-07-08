package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP message decryption.
 *
 * Unlocks recipient secret keys, decrypts encrypted data packets, verifies MDC
 * when present, and reports structured [SecurityProblem] values on failure.
 */

import java.io.ByteArrayInputStream
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder

/**
 * Parameters for decrypting an OpenPGP message.
 *
 * @property ciphertext Armored or binary encrypted message.
 * @property secretKeyRingArmored Recipient secret key ring.
 * @property passphrase Passphrase to unlock the matching secret subkey.
 */
data class DecryptRequest(
    val ciphertext: ByteArray,
    val secretKeyRingArmored: ByteArray,
    val passphrase: CharArray,
)

/**
 * Result of a successful decryption.
 *
 * @property plaintext Literal data payload bytes.
 * @property fileName Filename from the literal data packet, if any.
 * @property verified `true` when MDC integrity verification succeeded.
 * @property securityProblems Non-fatal security issues (e.g. missing MDC).
 */
data class DecryptResult(
    val plaintext: ByteArray,
    val fileName: String?,
    val verified: Boolean,
    val securityProblems: List<SecurityProblem>,
)

/** Decrypts OpenPGP messages and validates integrity protection. */
class PgpDecryptor {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Decrypts [request.ciphertext] using a matching key from [request.secretKeyRingArmored].
     *
     * @throws PgpException if no matching key, wrong passphrase, or parse failure.
     */
    fun decrypt(request: DecryptRequest): DecryptResult {
        val secretRing = PGPUtil.getDecoderStream(ByteArrayInputStream(request.secretKeyRingArmored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }

        val secretKeyDecryptor = PgpOperators.secretKeyDecryptor(request.passphrase, preferBc = false)
        val bcSecretKeyDecryptor = PgpOperators.secretKeyDecryptor(request.passphrase, preferBc = true)

        val encryptedList = PgpStreams.readEncryptedList(request.ciphertext, fingerprintCalculator)

        var encryptedData: PGPPublicKeyEncryptedData? = null
        var clearFactory: PGPObjectFactory? = null
        var lastError: Exception? = null

        val pbeIter = encryptedList.encryptedDataObjects
        while (pbeIter.hasNext()) {
            val pbe = pbeIter.next() as PGPPublicKeyEncryptedData
            val secretKey = secretRing.getSecretKey(pbe.keyID) ?: continue
            try {
                val privateKey = try {
                    secretKey.extractPrivateKey(
                        if (PgpOperators.useBcForPublicKey(secretKey.publicKey)) {
                            bcSecretKeyDecryptor
                        } else {
                            secretKeyDecryptor
                        },
                    )
                } catch (_: Exception) {
                    secretKey.extractPrivateKey(bcSecretKeyDecryptor)
                }
                val clearStream = decryptDataStream(pbe, privateKey)
                encryptedData = pbe
                clearFactory = PGPObjectFactory(clearStream, fingerprintCalculator)
                break
            } catch (e: Exception) {
                lastError = e
                continue
            }
        }

        val pbe = encryptedData ?: throw PgpException(
            lastError?.message ?: "No matching secret key or wrong passphrase for ciphertext",
        )
        val plainFactory = clearFactory ?: throw PgpException("Decryption failed")

        var message = plainFactory.nextObject()
        if (message is PGPCompressedData) {
            message = PGPObjectFactory(message.dataStream, fingerprintCalculator).nextObject()
        }

        val literal = message as PGPLiteralData
        val plaintext = literal.inputStream.use { PgpIo.readLimited(it) }

        val securityProblems = mutableListOf<SecurityProblem>()
        val verified = if (pbe.isIntegrityProtected) {
            val ok = pbe.verify()
            if (!ok) securityProblems.add(SecurityProblem.MDC_FAILURE)
            ok
        } else {
            securityProblems.add(SecurityProblem.UNSIGNED)
            false
        }

        return DecryptResult(
            plaintext = plaintext,
            fileName = literal.fileName,
            verified = verified,
            securityProblems = securityProblems,
        )
    }

    /** Opens the symmetrically encrypted payload stream, with JCA/BC decryptor fallback. */
    private fun decryptDataStream(pbe: PGPPublicKeyEncryptedData, privateKey: PGPPrivateKey) =
        try {
            pbe.getDataStream(JcePublicKeyDataDecryptorFactoryBuilder().build(privateKey))
        } catch (_: Exception) {
            pbe.getDataStream(BcPublicKeyDataDecryptorFactory(privateKey))
        }
}
