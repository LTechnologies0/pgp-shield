package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP message encryption.
 *
 * Wraps plaintext in a literal data packet, encrypts to one or more recipients
 * with AES-256 and integrity protection, and optionally ASCII-armors the result.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Date
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator

/**
 * Parameters for encrypting a message to OpenPGP recipients.
 *
 * @property plaintext Raw message bytes to encrypt.
 * @property recipientKeyRings Armored public or secret key rings (encryption subkeys used).
 * @property asciiArmor When `true`, wrap output in ASCII armor.
 * @property fileName Literal data packet filename metadata.
 */
data class EncryptRequest(
    val plaintext: ByteArray,
    val recipientKeyRings: List<ByteArray>,
    val asciiArmor: Boolean = true,
    val fileName: String = PGPLiteralData.CONSOLE,
)

/** Encrypted (and optionally armored) OpenPGP message bytes. */
data class EncryptResult(
    val ciphertext: ByteArray,
)

/** Encrypts data to OpenPGP public-key recipients. */
class PgpEncryptor {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Encrypts [request.plaintext] for all encryption-capable keys in [request.recipientKeyRings].
     *
     * @throws IllegalArgumentException if no encryption keys are found.
     */
    fun encrypt(request: EncryptRequest): EncryptResult {
        val recipientKeys = ArrayList<PGPPublicKey>()
        for (armored in request.recipientKeyRings) {
            recipientKeys.addAll(extractEncryptionKeys(armored))
        }
        val distinct = recipientKeys.distinctBy { it.keyID }
        require(distinct.isNotEmpty()) { "No encryption-capable recipient keys" }

        val literalBytes = ByteArrayOutputStream().use { literalOut ->
            val literalGen = PGPLiteralDataGenerator()
            val literalStream = literalGen.open(
                literalOut,
                PGPLiteralData.BINARY,
                request.fileName,
                request.plaintext.size.toLong(),
                Date(),
            )
            literalStream.write(request.plaintext)
            literalStream.close()
            literalGen.close()
            literalOut.toByteArray()
        }

        val encryptedGen = PGPEncryptedDataGenerator(
            JcePGPDataEncryptorBuilder(PgpAlgorithmPolicy.defaultSymmetricAlgorithm)
                .setWithIntegrityPacket(true)
                .setSecureRandom(SecureRandomProvider.secureRandom),
        )

        for (key in distinct) {
            encryptedGen.addMethod(keyEncryptionGenerator(key))
        }

        val payload = ByteArrayOutputStream().use { encOut ->
            val encStream = encryptedGen.open(encOut, literalBytes.size.toLong())
            encStream.write(literalBytes)
            encStream.close()
            encOut.toByteArray()
        }

        val result = if (request.asciiArmor) {
            ByteArrayOutputStream().use { armoredOut ->
                ArmoredOutputStream(armoredOut).use { armor -> armor.write(payload) }
                armoredOut.toByteArray()
            }
        } else {
            payload
        }

        return EncryptResult(ciphertext = result)
    }

    /** Selects BC or JCA public-key encryption method generator for [key]. */
    private fun keyEncryptionGenerator(key: PGPPublicKey): PublicKeyKeyEncryptionMethodGenerator =
        if (key.algorithm in BC_PKE_ALGORITHMS) {
            BcPublicKeyKeyEncryptionMethodGenerator(key)
        } else {
            JcePublicKeyKeyEncryptionMethodGenerator(key)
        }

    companion object {
        private val BC_PKE_ALGORITHMS = setOf(
            PGPPublicKey.ECDH,
            PGPPublicKey.ECDSA,
            PGPPublicKey.EC,
            PublicKeyAlgorithmTags.X25519,
            PublicKeyAlgorithmTags.X448,
        )
    }

    /** Extracts encryption-capable public keys from an armored key ring. */
    private fun extractEncryptionKeys(armored: ByteArray): List<PGPPublicKey> {
        val keys = ArrayList<PGPPublicKey>()
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            when (val obj = PGPObjectFactory(input, fingerprintCalculator).nextObject()) {
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
