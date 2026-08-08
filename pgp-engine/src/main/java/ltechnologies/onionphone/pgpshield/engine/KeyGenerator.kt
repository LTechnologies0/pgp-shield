package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP key ring generation.
 *
 * Creates a new master signing key with encryption and authentication subkeys,
 * applies user ID certification, passphrase-protects secret material, and returns
 * ASCII-armored public and secret key rings.
 *
 * Secret-key S2K protection is applied **in parallel** after an unprotected ring
 * is assembled. Elliptic-curve pair generation is cheap; sequential S2K on three
 * packets was the dominant cost.
 */

import java.io.ByteArrayOutputStream
import java.util.Date
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder

/**
 * Parameters for generating a new OpenPGP key ring.
 *
 * @property userId RFC 4880 user ID string (typically `Name <email@example.com>`).
 * @property passphrase Passphrase used to encrypt the secret key ring.
 * @property algorithmType Primary signing algorithm preset.
 * @property rsaBits RSA modulus size when [algorithmType] is [KeyAlgorithmType.RSA].
 */
data class GenerateKeyRequest(
    val userId: String,
    val passphrase: CharArray,
    val algorithmType: KeyAlgorithmType = KeyAlgorithmType.RSA,
    val rsaBits: Int = 3072,
    val keyFormat: KeyFormat = KeyFormat.V4,
    /** Master key validity in seconds from creation; `0` = no expiry. */
    val expirySeconds: Long = 0L,
    /**
     * When `true` and [algorithmType] is Ed25519, emit native Ed25519/X25519 tags
     * on v4 packets (RFC 9580). Default `false` keeps legacy EDDSA/ECDH for GnuPG.
     */
    val preferNativeCurveTags: Boolean = false,
)

/**
 * Result of a successful key ring generation.
 *
 * @property publicArmored ASCII-armored public key ring bytes.
 * @property secretArmored ASCII-armored secret key ring bytes.
 * @property masterKeyId 64-bit key ID of the primary signing key.
 */
data class GeneratedKeyRing(
    val publicArmored: ByteArray,
    val secretArmored: ByteArray,
    val masterKeyId: Long,
)

/** Generates new OpenPGP key rings with master, encryption, and authentication subkeys. */
class KeyGenerator {
    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Generates a complete key ring from [request].
     *
     * Suspends while master / encrypt / auth key pairs are built in parallel on
     * [Dispatchers.Default], then protects secret packets with S2K in parallel.
     *
     * @throws IllegalArgumentException if RSA bit length is not in [PgpAlgorithmPolicy.allowedRsaBits].
     */
    suspend fun generateKeyRing(request: GenerateKeyRequest): GeneratedKeyRing {
        require(request.algorithmType != KeyAlgorithmType.RSA || request.rsaBits in PgpAlgorithmPolicy.allowedRsaBits) {
            "RSA key size must be one of ${PgpAlgorithmPolicy.allowedRsaBits}"
        }
        if (request.keyFormat == KeyFormat.V6) {
            return generateV6KeyRing(request)
        }
        val now = Date()
        CryptoProgress.stage(CryptoStage.GENERATE_KEY_PAIRS)
        val native = request.preferNativeCurveTags
        val (master, encSub, authSub) = coroutineScope {
            val masterDef = async(Dispatchers.Default) {
                KeyPairFactory.masterSigningPair(request.algorithmType, request.rsaBits, now, native)
            }
            val encDef = async(Dispatchers.Default) {
                KeyPairFactory.encryptionSubkeyPair(request.algorithmType, request.rsaBits, now, native)
            }
            val authDef = async(Dispatchers.Default) {
                KeyPairFactory.authenticationSubkeyPair(request.algorithmType, request.rsaBits, now, native)
            }
            Triple(masterDef.await(), encDef.await(), authDef.await())
        }
        return buildRing(
            request,
            master.pair,
            encSub.pair,
            authSub.pair,
            master.useBcLightweight || encSub.useBcLightweight || authSub.useBcLightweight,
            aeadProtect = true,
        )
    }

    /**
     * RFC 9580 v6 keys via BC [org.bouncycastle.openpgp.api.bc.BcOpenPGPKeyGenerator].
     *
     * Supported presets: Ed25519+X25519, Ed448+X448, RSA. Other algorithm types
     * fall back to the classic v4 [buildRing] path.
     */
    private fun generateV6KeyRing(request: GenerateKeyRequest): GeneratedKeyRing {
        CryptoProgress.stage(CryptoStage.GENERATE_KEY_PAIRS)
        val version = 6
        val gen = org.bouncycastle.openpgp.api.bc.BcOpenPGPKeyGenerator(version, Date(), true)
        val withPrimary = when (request.algorithmType) {
            KeyAlgorithmType.ED25519 -> gen.ed25519x25519Key(request.userId)
            KeyAlgorithmType.ED448 -> gen.ed448x448Key(request.userId)
            KeyAlgorithmType.RSA -> gen.compositeRSAKey(request.rsaBits, request.userId)
            else -> {
                // BC high-level API has no NIST/Brainpool presets; use v4 assembly.
                return kotlinx.coroutines.runBlocking {
                    val now = Date()
                    val master = KeyPairFactory.masterSigningPair(request.algorithmType, request.rsaBits, now)
                    val enc = KeyPairFactory.encryptionSubkeyPair(request.algorithmType, request.rsaBits, now)
                    val auth = KeyPairFactory.authenticationSubkeyPair(request.algorithmType, request.rsaBits, now)
                    buildRing(
                        request.copy(keyFormat = KeyFormat.V4),
                        master.pair,
                        enc.pair,
                        auth.pair,
                        master.useBcLightweight || enc.useBcLightweight || auth.useBcLightweight,
                        aeadProtect = true,
                    )
                }
            }
        }
        CryptoProgress.stage(CryptoStage.S2K_PROTECT)
        // build() without passphrase yields clear secret material; we protect with our
        // encryptors so unlock stays compatible with [PgpOperators.extractPrivateKey].
        val openPgpKey = withPrimary.addEncryptionSubkey().build()
        val unprotected = openPgpKey.pgpSecretKeyRing
        val secretKeys = unprotected.secretKeys.asSequence().toList()
        val protectedKeys = secretKeys.map { sk ->
            val encryptor = PgpOperators.aeadSecretKeyEncryptor(request.passphrase, sk.publicKey)
            PGPSecretKey.copyWithNewPassword(sk, null, encryptor)
        }
        CryptoProgress.stage(CryptoStage.ARMOR)
        val secretRing = PGPSecretKeyRing(protectedKeys)
        val publicArmored = openPgpKey.toCertificate().toAsciiArmoredString().toByteArray(Charsets.UTF_8)
        val secretArmored = armor(secretRing.encoded)
        return GeneratedKeyRing(
            publicArmored = publicArmored,
            secretArmored = secretArmored,
            masterKeyId = secretRing.secretKey.keyID,
        )
    }

    /** Blocking wrapper for JVM unit tests and sync call sites. */
    fun generateKeyRingBlocking(request: GenerateKeyRequest): GeneratedKeyRing =
        kotlinx.coroutines.runBlocking { generateKeyRing(request) }

    /**
     * Assembles certifications with **unprotected** secret packets (null encryptor),
     * then passphrase-protects every secret key in parallel. Wall-clock S2K cost is
     * ~1× instead of 3× sequential.
     */
    private suspend fun buildRing(
        request: GenerateKeyRequest,
        masterPair: org.bouncycastle.openpgp.PGPKeyPair,
        encSubPair: org.bouncycastle.openpgp.PGPKeyPair,
        authSubPair: org.bouncycastle.openpgp.PGPKeyPair,
        useBcLightweight: Boolean,
        aeadProtect: Boolean = true,
    ): GeneratedKeyRing {
        val digestCalc = JcaPlatform.digestCalculators.get(HashAlgorithmTags.SHA1)
        val contentSignerBuilder: PGPContentSignerBuilder =
            PgpOperators.contentSignerBuilder(masterPair.publicKey, useBcLightweight)

        val hashedSubpackets = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
            if (request.expirySeconds > 0L) {
                setKeyExpirationTime(false, request.expirySeconds)
            }
            PgpAlgorithmPolicy.applyInteropPreferences(this, masterPair.publicKey)
        }.generate()
        val unhashedSubpackets = PGPSignatureSubpacketGenerator().apply {
            addSignerUserID(false, request.userId)
        }.generate()

        // null encryptor: skip S2K while binding signatures (private keys still in memory).
        val ringGenerator = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            masterPair,
            request.userId,
            digestCalc,
            hashedSubpackets,
            unhashedSubpackets,
            contentSignerBuilder,
            null,
        )
        addSubkey(ringGenerator, encSubPair, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE, request.expirySeconds)
        addSubkey(ringGenerator, authSubPair, KeyFlags.AUTHENTICATION, request.expirySeconds)

        val unprotected = ringGenerator.generateSecretKeyRing()
        val secretKeys = unprotected.secretKeys.asSequence().toList()
        CryptoProgress.stage(CryptoStage.S2K_PROTECT)
        val protectedKeys = BcParallel.map(secretKeys) { sk ->
            val encryptor = if (aeadProtect) {
                PgpOperators.aeadSecretKeyEncryptor(request.passphrase, sk.publicKey)
            } else {
                PgpOperators.secretKeyEncryptor(request.passphrase, useBcLightweight)
            }
            PGPSecretKey.copyWithNewPassword(sk, null, encryptor)
        }
        CryptoProgress.stage(CryptoStage.ARMOR)
        val secretRing = PGPSecretKeyRing(protectedKeys)
        return encodeRings(secretRing, masterPair.keyID)
    }

    /** Encodes secret and derived public rings and returns armored bytes plus master key ID. */
    private fun encodeRings(secretRing: PGPSecretKeyRing, masterKeyId: Long): GeneratedKeyRing {
        val publicKeys = ArrayList<PGPPublicKey>()
        val secretIter = secretRing.secretKeys
        while (secretIter.hasNext()) {
            publicKeys.add(secretIter.next().publicKey)
        }
        val publicRing = PGPPublicKeyRing(publicKeys)
        return GeneratedKeyRing(
            publicArmored = armor(publicRing.encoded),
            secretArmored = armor(secretRing.encoded),
            masterKeyId = masterKeyId,
        )
    }

    /** Registers a subkey on the ring generator with the given capability flags. */
    private fun addSubkey(
        ringGenerator: PGPKeyRingGenerator,
        subPair: org.bouncycastle.openpgp.PGPKeyPair,
        flags: Int,
        expirySeconds: Long = 0L,
    ) {
        val hashed = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, flags)
            if (expirySeconds > 0L) {
                setKeyExpirationTime(false, expirySeconds)
            }
        }.generate()
        ringGenerator.addSubKey(subPair, hashed, null)
    }

    /** Wraps binary OpenPGP data in ASCII armor. */
    private fun armor(data: ByteArray): ByteArray =
        ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> armor.write(data) }
            out.toByteArray()
        }
}
