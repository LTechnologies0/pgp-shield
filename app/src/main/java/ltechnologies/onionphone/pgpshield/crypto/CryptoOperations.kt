package ltechnologies.onionphone.pgpshield.crypto

/**
 * High-level cryptographic facade over the low-level engine components.
 *
 * This layer packages caller arguments into engine request objects and exposes
 * a single, dependency-injected surface for key management, encryption,
 * signing, S/MIME and GnuPG tar operations used throughout the app.
 */

import ltechnologies.onionphone.pgpshield.engine.ChangePassphraseRequest
import ltechnologies.onionphone.pgpshield.engine.DecryptRequest
import ltechnologies.onionphone.pgpshield.engine.EncryptRequest
import ltechnologies.onionphone.pgpshield.engine.GenerateKeyRequest
import ltechnologies.onionphone.pgpshield.engine.GeneratedKeyRing
import ltechnologies.onionphone.pgpshield.engine.KeyAlgorithmType
import ltechnologies.onionphone.pgpshield.engine.KeyGenerator
import ltechnologies.onionphone.pgpshield.engine.KeyPassphraseChanger
import ltechnologies.onionphone.pgpshield.engine.AddSubkeyRequest
import ltechnologies.onionphone.pgpshield.engine.SubkeyAdder
import ltechnologies.onionphone.pgpshield.engine.SubkeyType
import ltechnologies.onionphone.pgpshield.engine.CertifyKeyRequest
import ltechnologies.onionphone.pgpshield.engine.GpgTar
import ltechnologies.onionphone.pgpshield.engine.GpgTarDecryptRequest
import ltechnologies.onionphone.pgpshield.engine.GpgTarEncryptRequest
import ltechnologies.onionphone.pgpshield.engine.KeyCertifier
import ltechnologies.onionphone.pgpshield.engine.NamedFile
import ltechnologies.onionphone.pgpshield.engine.PgpDecryptor
import ltechnologies.onionphone.pgpshield.engine.PgpEncryptor
import ltechnologies.onionphone.pgpshield.engine.PgpSigner
import ltechnologies.onionphone.pgpshield.engine.PgpVerifier
import ltechnologies.onionphone.pgpshield.engine.RevocationCertGenerator
import ltechnologies.onionphone.pgpshield.engine.RevocationCertRequest
import ltechnologies.onionphone.pgpshield.engine.SignRequest
import ltechnologies.onionphone.pgpshield.engine.SmimeEngine
import ltechnologies.onionphone.pgpshield.engine.SmartCardPort
import ltechnologies.onionphone.pgpshield.engine.SymmetricCipher
import ltechnologies.onionphone.pgpshield.engine.SymmetricDecryptRequest
import ltechnologies.onionphone.pgpshield.engine.SymmetricEncryptRequest
import ltechnologies.onionphone.pgpshield.engine.UserIdEditRequest
import ltechnologies.onionphone.pgpshield.engine.UserIdManager
import ltechnologies.onionphone.pgpshield.engine.VerifyRequest
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Singleton coordinator that delegates to individual engine helpers.
 *
 * Each public function corresponds to one OpenPGP/S-MIME primitive and simply
 * builds the matching engine request. Callers pass raw byte/char material;
 * zeroing of passphrase buffers remains the responsibility of the caller.
 */
@Singleton
class CryptoOperations @Inject constructor() {
    private val keyGenerator = KeyGenerator()
    private val encryptor = PgpEncryptor()
    private val decryptor = PgpDecryptor()
    private val signer = PgpSigner()
    private val verifier = PgpVerifier()
    private val passphraseChanger = KeyPassphraseChanger()
    private val subkeyAdder = SubkeyAdder()
    private val revocationCertGenerator = RevocationCertGenerator()
    private val keyCertifier = KeyCertifier()
    private val userIdManager = UserIdManager()
    private val gpgTar = GpgTar()
    private val symmetricCipher = SymmetricCipher()
    private val smimeEngine = SmimeEngine()
    // ponytail: NFC/smart-card stub; swap for real SmartCardPort when hardware wired
    val smartCardPort: SmartCardPort = object : SmartCardPort {}

    /**
     * Generates a new secret/public key ring for [userId].
     *
     * @param passphrase Passphrase protecting the new secret key.
     * @param algorithmType Key algorithm family (defaults to RSA).
     * @param rsaBits RSA key size when [algorithmType] is RSA.
     */
    fun generateKey(
        userId: String,
        passphrase: CharArray,
        algorithmType: KeyAlgorithmType = KeyAlgorithmType.RSA,
        rsaBits: Int = 3072,
    ): GeneratedKeyRing =
        keyGenerator.generateKeyRing(
            GenerateKeyRequest(userId, passphrase, algorithmType, rsaBits),
        )

    /**
     * Encrypts [plaintext] to one or more recipients.
     *
     * @param recipientPublicArmored Recipient public key rings.
     * @param asciiArmor Whether to ASCII-armor the output.
     * @param fileName Embedded literal-data filename (`_CONSOLE` for text).
     */
    fun encrypt(
        plaintext: ByteArray,
        recipientPublicArmored: List<ByteArray>,
        asciiArmor: Boolean = true,
        fileName: String = "_CONSOLE",
    ) =
        encryptor.encrypt(
            EncryptRequest(
                plaintext = plaintext,
                recipientKeyRings = recipientPublicArmored,
                asciiArmor = asciiArmor,
                fileName = fileName,
            ),
        )

    /** Decrypts [ciphertext] using the given secret key ring and [passphrase]. */
    fun decrypt(ciphertext: ByteArray, secretArmored: ByteArray, passphrase: CharArray) =
        decryptor.decrypt(
            DecryptRequest(
                ciphertext = ciphertext,
                secretKeyRingArmored = secretArmored,
                passphrase = passphrase,
            ),
        )

    /**
     * Signs [data] with the given secret key.
     *
     * @param detachedBinary When `true`, produces a detached binary signature.
     */
    fun sign(
        data: ByteArray,
        secretArmored: ByteArray,
        passphrase: CharArray,
        detachedBinary: Boolean = false,
    ) =
        signer.sign(
            SignRequest(
                data = data,
                secretKeyRingArmored = secretArmored,
                passphrase = passphrase,
                detachedBinary = detachedBinary,
            ),
        )

    /**
     * Verifies a signature against candidate public keys.
     *
     * @param message Original message for detached-signature verification.
     * @param binaryDocument Whether the signed document is binary.
     */
    fun verify(
        signedData: ByteArray,
        publicArmored: List<ByteArray>,
        message: ByteArray? = null,
        binaryDocument: Boolean = false,
    ) =
        verifier.verify(
            VerifyRequest(
                signedOrDetached = signedData,
                detachedMessage = message,
                publicKeyRingsArmored = publicArmored,
                binaryDocument = binaryDocument,
            ),
        )

    /** Re-encrypts the secret key ring, replacing [oldPassphrase] with [newPassphrase]. */
    fun changePassphrase(secretArmored: ByteArray, oldPassphrase: CharArray, newPassphrase: CharArray): ByteArray =
        passphraseChanger.changePassphrase(
            ChangePassphraseRequest(
                secretKeyRingArmored = secretArmored,
                oldPassphrase = oldPassphrase,
                newPassphrase = newPassphrase,
            ),
        )

    /**
     * Adds a subkey of [subkeyType] to an existing secret key ring.
     *
     * @param rsaBits RSA size used when the subkey is an RSA key.
     */
    fun addSubkey(
        secretArmored: ByteArray,
        passphrase: CharArray,
        subkeyType: SubkeyType,
        rsaBits: Int = 3072,
    ): ByteArray =
        subkeyAdder.addSubkey(
            AddSubkeyRequest(
                secretKeyRingArmored = secretArmored,
                passphrase = passphrase,
                subkeyType = subkeyType,
                rsaBits = rsaBits,
            ),
        )

    /** Produces a revocation certificate for the secret key, with optional [reasonText]. */
    fun generateRevocationCert(secretArmored: ByteArray, passphrase: CharArray, reasonText: String = ""): ByteArray =
        revocationCertGenerator.generate(
            RevocationCertRequest(
                secretKeyRingArmored = secretArmored,
                passphrase = passphrase,
                reasonText = reasonText,
            ),
        )

    /**
     * Certifies (signs) [userId] on [targetPublicArmored] using the certifier's
     * secret key, establishing a trust signature.
     */
    fun certifyKey(
        certifierSecretArmored: ByteArray,
        certifierPassphrase: CharArray,
        targetPublicArmored: ByteArray,
        userId: String,
    ) = keyCertifier.certify(
        CertifyKeyRequest(
            certifierSecretArmored = certifierSecretArmored,
            certifierPassphrase = certifierPassphrase,
            targetPublicArmored = targetPublicArmored,
            userId = userId,
        ),
    )

    /** Adds a new [userId] identity to the secret key ring. */
    fun addUserId(secretArmored: ByteArray, passphrase: CharArray, userId: String): ByteArray =
        userIdManager.addUserId(
            UserIdEditRequest(
                secretKeyRingArmored = secretArmored,
                passphrase = passphrase,
                userId = userId,
            ),
        )

    /** Encrypts a set of [files] into a single GnuPG-compatible encrypted tar. */
    fun encryptTar(files: List<NamedFile>, recipientPublicArmored: List<ByteArray>, asciiArmor: Boolean = true) =
        gpgTar.encrypt(
            GpgTarEncryptRequest(
                files = files,
                recipientKeyRings = recipientPublicArmored,
                asciiArmor = asciiArmor,
            ),
        )

    /** Decrypts a GnuPG encrypted tar back into its constituent [NamedFile]s. */
    fun decryptTar(ciphertext: ByteArray, secretArmored: ByteArray, passphrase: CharArray): List<NamedFile> =
        gpgTar.decrypt(
            GpgTarDecryptRequest(
                ciphertext = ciphertext,
                secretKeyRingArmored = secretArmored,
                passphrase = passphrase,
            ),
        )

    /** Password-based (symmetric) encryption of [plaintext]. */
    fun symmetricEncrypt(plaintext: ByteArray, password: CharArray): ByteArray =
        symmetricCipher.encrypt(SymmetricEncryptRequest(plaintext, password))

    /** Password-based (symmetric) decryption of [ciphertext]. */
    fun symmetricDecrypt(ciphertext: ByteArray, password: CharArray): ByteArray =
        symmetricCipher.decrypt(SymmetricDecryptRequest(ciphertext, password))

    /** Encrypts [plaintext] using the S/MIME engine. */
    fun smimeEncrypt(plaintext: ByteArray): ByteArray = smimeEngine.encrypt(plaintext)

    /** Decrypts [ciphertext] using the S/MIME engine. */
    fun smimeDecrypt(ciphertext: ByteArray): ByteArray = smimeEngine.decrypt(ciphertext)
}
