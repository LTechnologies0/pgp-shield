package ltechnologies.onionphone.pgpshield.crypto

/**
 * High-level cryptographic facade over the low-level engine components.
 *
 * This layer packages caller arguments into engine request objects and exposes
 * a single, dependency-injected surface for key management, encryption,
 * signing, S/MIME and GnuPG tar operations used throughout the app.
 */

import ltechnologies.onionphone.pgpshield.engine.ChangePassphraseRequest
import ltechnologies.onionphone.pgpshield.engine.CryptoOperation
import ltechnologies.onionphone.pgpshield.engine.CryptoProgress
import ltechnologies.onionphone.pgpshield.engine.DecryptRequest
import ltechnologies.onionphone.pgpshield.engine.EncryptPlaintext
import ltechnologies.onionphone.pgpshield.engine.EncryptRequest
import ltechnologies.onionphone.pgpshield.engine.EncryptResult
import ltechnologies.onionphone.pgpshield.engine.GenerateKeyRequest
import ltechnologies.onionphone.pgpshield.engine.GeneratedKeyRing
import ltechnologies.onionphone.pgpshield.engine.KeyAlgorithmType
import ltechnologies.onionphone.pgpshield.engine.KeyFormat
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
import ltechnologies.onionphone.pgpshield.engine.MessageCompression
import ltechnologies.onionphone.pgpshield.engine.MessageIntegrity
import ltechnologies.onionphone.pgpshield.engine.NamedFile
import ltechnologies.onionphone.pgpshield.engine.PgpDecryptor
import ltechnologies.onionphone.pgpshield.engine.PgpEncryptor
import ltechnologies.onionphone.pgpshield.engine.PgpRecipientCapabilities
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
class CryptoOperations @Inject constructor(
    val smartCardPort: SmartCardPort,
) {
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
        keyFormat: KeyFormat = KeyFormat.V4,
        expirySeconds: Long = 0L,
        preferNativeCurveTags: Boolean = false,
    ): GeneratedKeyRing =
        CryptoProgress.measure(CryptoOperation.KEYGEN) {
            kotlinx.coroutines.runBlocking {
                keyGenerator.generateKeyRing(
                    GenerateKeyRequest(
                        userId, passphrase, algorithmType, rsaBits, keyFormat, expirySeconds,
                        preferNativeCurveTags = preferNativeCurveTags,
                    ),
                )
            }
        }.first

    /** Suspend variant — preferred from coroutines (no nested runBlocking). */
    suspend fun generateKeySuspending(
        userId: String,
        passphrase: CharArray,
        algorithmType: KeyAlgorithmType = KeyAlgorithmType.RSA,
        rsaBits: Int = 3072,
        keyFormat: KeyFormat = KeyFormat.V4,
        expirySeconds: Long = 0L,
        preferNativeCurveTags: Boolean = false,
    ): GeneratedKeyRing =
        CryptoProgress.measureSuspend(CryptoOperation.KEYGEN) {
            keyGenerator.generateKeyRing(
                GenerateKeyRequest(
                    userId, passphrase, algorithmType, rsaBits, keyFormat, expirySeconds,
                    preferNativeCurveTags = preferNativeCurveTags,
                ),
            )
        }.first

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
        integrity: MessageIntegrity = MessageIntegrity.SEIPD_V2_AEAD,
        compression: MessageCompression = MessageCompression.NONE,
        signSecretArmored: ByteArray? = null,
        signPassphrase: CharArray? = null,
        passphrase: CharArray? = null,
    ) =
        CryptoProgress.measure(CryptoOperation.ENCRYPT) {
            encryptor.encrypt(
                EncryptRequest(
                    plaintext = plaintext,
                    recipientKeyRings = recipientPublicArmored,
                    asciiArmor = asciiArmor,
                    fileName = fileName,
                    integrity = integrity,
                    // Honor requested integrity: SEIPDv2 falls back only via resolveIntegrity
                    // (fail-closed when recipients lack Features), never a silent MDC downgrade.
                    forceIntegrity = integrity == MessageIntegrity.LIBREPGP_V5_AEAD,
                    compression = compression,
                    signSecretRingArmored = signSecretArmored,
                    signPassphrase = signPassphrase,
                    passphrase = passphrase,
                ),
            )
        }.first

    /**
     * Encrypts many plaintexts to the same recipients (parse rings once, parallel BC).
     *
     * Prefer from coroutines; [parallelism] caps concurrent session encrypts.
     */
    suspend fun encryptMany(
        plaintexts: List<EncryptPlaintext>,
        recipientPublicArmored: List<ByteArray>,
        parallelism: Int = 4,
        integrity: MessageIntegrity = MessageIntegrity.SEIPD_V2_AEAD,
        compression: MessageCompression = MessageCompression.NONE,
    ): List<EncryptResult> =
        CryptoProgress.measureSuspend(CryptoOperation.ENCRYPT_MANY) {
            encryptor.encryptMany(
                plaintexts,
                recipientPublicArmored,
                parallelism,
                integrity = integrity,
                compression = compression,
            )
        }.first

    /** Suspend encrypt — no nested runBlocking when already on a dispatcher. */
    suspend fun encryptSuspending(
        plaintext: ByteArray,
        recipientPublicArmored: List<ByteArray>,
        asciiArmor: Boolean = true,
        fileName: String = "_CONSOLE",
        integrity: MessageIntegrity = MessageIntegrity.SEIPD_V2_AEAD,
        compression: MessageCompression = MessageCompression.NONE,
        signSecretArmored: ByteArray? = null,
        signPassphrase: CharArray? = null,
    ) =
        CryptoProgress.measureSuspend(CryptoOperation.ENCRYPT) {
            encryptor.encryptSuspending(
                EncryptRequest(
                    plaintext = plaintext,
                    recipientKeyRings = recipientPublicArmored,
                    asciiArmor = asciiArmor,
                    fileName = fileName,
                    integrity = integrity,
                    forceIntegrity = integrity == MessageIntegrity.LIBREPGP_V5_AEAD,
                    compression = compression,
                    signSecretRingArmored = signSecretArmored,
                    signPassphrase = signPassphrase,
                ),
            )
        }.first

    /** Decrypts [ciphertext] using the given secret key ring and [passphrase]. */
    fun decrypt(
        ciphertext: ByteArray,
        secretArmored: ByteArray,
        passphrase: CharArray,
        signerPublicArmored: List<ByteArray> = emptyList(),
    ) =
        CryptoProgress.measure(CryptoOperation.DECRYPT) {
            decryptor.decrypt(
                DecryptRequest(
                    ciphertext = ciphertext,
                    secretKeyRingArmored = secretArmored,
                    passphrase = passphrase,
                    signerPublicKeyRingsArmored = signerPublicArmored,
                    smartCard = smartCardPort.takeIf { it.isAvailable() },
                ),
            )
        }.first

    /**
     * Signs [data] with the given secret key.
     *
     * @param detachedBinary When `true`, produces a detached binary signature.
     * @param inlineBinary When `true`, produces one-pass + literal + signature.
     */
    fun sign(
        data: ByteArray,
        secretArmored: ByteArray,
        passphrase: CharArray,
        detachedBinary: Boolean = false,
        inlineBinary: Boolean = false,
    ) =
        CryptoProgress.measure(CryptoOperation.SIGN) {
            signer.sign(
                SignRequest(
                    data = data,
                    secretKeyRingArmored = secretArmored,
                    passphrase = passphrase,
                    detachedBinary = detachedBinary,
                    inlineBinary = inlineBinary,
                    cleartext = !detachedBinary && !inlineBinary,
                    smartCard = smartCardPort.takeIf { it.isAvailable() },
                ),
            )
        }.first

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
        CryptoProgress.measure(CryptoOperation.VERIFY) {
            verifier.verify(
                VerifyRequest(
                    signedOrDetached = signedData,
                    detachedMessage = message,
                    publicKeyRingsArmored = publicArmored,
                    binaryDocument = binaryDocument,
                ),
            )
        }.first

    /** Re-encrypts the secret key ring, replacing [oldPassphrase] with [newPassphrase]. */
    fun changePassphrase(secretArmored: ByteArray, oldPassphrase: CharArray, newPassphrase: CharArray): ByteArray =
        CryptoProgress.measure(CryptoOperation.CHANGE_PASSPHRASE) {
            passphraseChanger.changePassphrase(
                ChangePassphraseRequest(
                    secretKeyRingArmored = secretArmored,
                    oldPassphrase = oldPassphrase,
                    newPassphrase = newPassphrase,
                    aeadProtect = true,
                ),
            )
        }.first

    /**
     * If [secretArmored] still uses classic S2K, rewraps in place with Argon2+AEAD using the
     * same [passphrase]. Returns the upgraded armored ring, or `null` when already modern.
     */
    fun upgradeSecretProtectionIfNeeded(secretArmored: ByteArray, passphrase: CharArray): ByteArray? {
        if (!PgpRecipientCapabilities.needsAeadSecretUpgrade(secretArmored)) return null
        val oldPass = passphrase.copyOf()
        val newPass = passphrase.copyOf()
        return try {
            changePassphrase(secretArmored, oldPass, newPass)
        } finally {
            oldPass.fill('\u0000')
            newPass.fill('\u0000')
        }
    }

    /** Suspend passphrase rewrap (parallel S2K, no nested runBlocking). */
    suspend fun changePassphraseSuspending(
        secretArmored: ByteArray,
        oldPassphrase: CharArray,
        newPassphrase: CharArray,
    ): ByteArray =
        CryptoProgress.measureSuspend(CryptoOperation.CHANGE_PASSPHRASE) {
            passphraseChanger.changePassphraseSuspending(
                ChangePassphraseRequest(
                    secretKeyRingArmored = secretArmored,
                    oldPassphrase = oldPassphrase,
                    newPassphrase = newPassphrase,
                    aeadProtect = true,
                ),
            )
        }.first

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
        expirySeconds: Long = 0L,
    ): ByteArray =
        CryptoProgress.measure(CryptoOperation.ADD_SUBKEY) {
            subkeyAdder.addSubkey(
                AddSubkeyRequest(
                    secretKeyRingArmored = secretArmored,
                    passphrase = passphrase,
                    subkeyType = subkeyType,
                    rsaBits = rsaBits,
                    expirySeconds = expirySeconds,
                ),
            )
        }.first

    fun generateRevocationCert(
        secretArmored: ByteArray,
        passphrase: CharArray,
        reason: Byte = 0,
        reasonText: String = "",
        subkeyId: Long? = null,
    ): ByteArray =
        revocationCertGenerator.generate(
            RevocationCertRequest(
                secretKeyRingArmored = secretArmored,
                passphrase = passphrase,
                reason = reason,
                reasonText = reasonText,
                subkeyId = subkeyId,
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

    /** Encrypts [plaintext] to [recipientCerts] using CMS EnvelopedData. */
    fun smimeEncrypt(plaintext: ByteArray, recipientCerts: List<java.security.cert.X509Certificate>): ByteArray =
        smimeEngine.encrypt(plaintext, recipientCerts)

    /** Decrypts CMS EnvelopedData with [privateKey]. */
    fun smimeDecrypt(ciphertext: ByteArray, privateKey: java.security.PrivateKey): ByteArray =
        smimeEngine.decrypt(ciphertext, privateKey)

    /** CMS sign (attached). */
    fun smimeSign(
        content: ByteArray,
        privateKey: java.security.PrivateKey,
        certificate: java.security.cert.X509Certificate,
    ): ByteArray = smimeEngine.sign(content, privateKey, certificate)

    /** CMS verify. */
    fun smimeVerify(
        signedCms: ByteArray,
        trustAnchors: List<java.security.cert.X509Certificate> = emptyList(),
    ) = smimeEngine.verify(signedCms, trustAnchors)

    /** Import PKCS#12 identities. */
    fun smimeImportPkcs12(pkcs12: ByteArray, password: CharArray) =
        smimeEngine.importPkcs12(pkcs12, password)

    val smime: SmimeEngine get() = smimeEngine
}
