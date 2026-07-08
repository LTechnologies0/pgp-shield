package ltechnologies.onionphone.pgpshield.engine

import java.io.ByteArrayInputStream
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

object PgpTestSupport {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    fun generateRsa(userId: String, passphrase: CharArray, rsaBits: Int = 2048): GeneratedKeyRing =
        KeyGenerator().generateKeyRing(
            GenerateKeyRequest(
                userId = userId,
                passphrase = passphrase,
                algorithmType = KeyAlgorithmType.RSA,
                rsaBits = rsaBits,
            ),
        )

    fun generateOrAssume(type: KeyAlgorithmType, userId: String, passphrase: CharArray): GeneratedKeyRing {
        return try {
            KeyGenerator().generateKeyRing(
                GenerateKeyRequest(
                    userId = userId,
                    passphrase = passphrase,
                    algorithmType = type,
                    rsaBits = if (type == KeyAlgorithmType.RSA) 3072 else 0,
                ),
            )
        } catch (e: Exception) {
            assumeTrue(false, "${type.name} unavailable on this JVM: ${e.message}")
            error("unreachable")
        }
    }

    fun encrypt(plaintext: ByteArray, recipients: List<ByteArray>): ByteArray =
        PgpEncryptor().encrypt(EncryptRequest(plaintext, recipients)).ciphertext

    fun decrypt(ciphertext: ByteArray, secret: ByteArray, passphrase: CharArray): ByteArray =
        PgpDecryptor().decrypt(DecryptRequest(ciphertext, secret, passphrase)).plaintext

    fun sign(message: ByteArray, secret: ByteArray, passphrase: CharArray, detached: Boolean = false): ByteArray =
        PgpSigner().sign(SignRequest(message, secret, passphrase, detachedBinary = detached)).output

    fun verify(signed: ByteArray, publicKeys: List<ByteArray>, message: ByteArray? = null): VerifyResult =
        PgpVerifier().verify(
            VerifyRequest(
                signedOrDetached = signed,
                publicKeyRingsArmored = publicKeys,
                detachedMessage = message,
                binaryDocument = message != null,
            ),
        )

    fun subkeyIds(secretArmored: ByteArray): List<Long> {
        val info = KeyRingReader().readSecretKeyRing(secretArmored.inputStream())
        return info.subkeys.map { it.keyId }
    }

    fun encryptionSubkeyId(secretArmored: ByteArray): Long {
        val info = KeyRingReader().readSecretKeyRing(secretArmored.inputStream())
        return info.subkeys.firstOrNull { it.keyId != info.masterKeyId }?.keyId
            ?: error("No encryption subkey found")
    }

    fun assertRevoked(publicArmored: ByteArray) {
        val info = KeyRingReader().readPublicKeyRing(publicArmored.inputStream())
        assertTrue(info.isRevoked, "Expected revoked public key ring")
    }

    fun assertCertificationType(publicArmored: ByteArray, userId: String, type: CertificationType) {
        val key = loadMasterPublic(publicArmored)
        val sigs = key.getSignaturesForID(userId) ?: error("No certifications for $userId")
        var found = false
        while (sigs.hasNext()) {
            val sig = sigs.next()
            if (sig.signatureType == type.toSignatureType()) {
                found = true
                break
            }
        }
        assertTrue(found, "Missing ${type.name} certification on $userId")
    }

    private fun loadMasterPublic(publicArmored: ByteArray): PGPPublicKey {
        val ring = PGPUtil.getDecoderStream(ByteArrayInputStream(publicArmored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPPublicKeyRing
        }
        return ring.publicKey
    }
}
