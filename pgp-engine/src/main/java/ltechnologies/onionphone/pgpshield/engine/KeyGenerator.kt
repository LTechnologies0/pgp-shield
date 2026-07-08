package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP key ring generation.
 *
 * Creates a new master signing key with encryption and authentication subkeys,
 * applies user ID certification, passphrase-protects secret material, and returns
 * ASCII-armored public and secret key rings.
 */

import java.io.ByteArrayOutputStream
import java.util.Date
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
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
     * @throws IllegalArgumentException if RSA bit length is not in [PgpAlgorithmPolicy.allowedRsaBits].
     */
    fun generateKeyRing(request: GenerateKeyRequest): GeneratedKeyRing {
        require(request.algorithmType != KeyAlgorithmType.RSA || request.rsaBits in PgpAlgorithmPolicy.allowedRsaBits) {
            "RSA key size must be one of ${PgpAlgorithmPolicy.allowedRsaBits}"
        }
        val now = Date()
        val master = KeyPairFactory.masterSigningPair(request.algorithmType, request.rsaBits, now)
        val encSub = KeyPairFactory.encryptionSubkeyPair(request.algorithmType, request.rsaBits, now)
        val authSub = KeyPairFactory.authenticationSubkeyPair(request.algorithmType, request.rsaBits, now)
        return buildRing(
            request,
            master.pair,
            encSub.pair,
            authSub.pair,
            master.useBcLightweight || encSub.useBcLightweight || authSub.useBcLightweight,
        )
    }

    /** Assembles the key ring, adds subkeys with flags, and armors the output. */
    private fun buildRing(
        request: GenerateKeyRequest,
        masterPair: org.bouncycastle.openpgp.PGPKeyPair,
        encSubPair: org.bouncycastle.openpgp.PGPKeyPair,
        authSubPair: org.bouncycastle.openpgp.PGPKeyPair,
        useBcLightweight: Boolean,
    ): GeneratedKeyRing {
        val digestCalc = JcaPlatform.digestCalculators.get(HashAlgorithmTags.SHA1)
        val contentSignerBuilder: PGPContentSignerBuilder =
            PgpOperators.contentSignerBuilder(masterPair.publicKey.algorithm, useBcLightweight)
        val encryptor = PgpOperators.secretKeyEncryptor(request.passphrase, useBcLightweight)

        val hashedSubpackets = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA)
        }.generate()
        val unhashedSubpackets = PGPSignatureSubpacketGenerator().apply {
            addSignerUserID(false, request.userId)
        }.generate()

        val ringGenerator = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            masterPair,
            request.userId,
            digestCalc,
            hashedSubpackets,
            unhashedSubpackets,
            contentSignerBuilder,
            encryptor,
        )
        addSubkey(ringGenerator, encSubPair, KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE)
        addSubkey(ringGenerator, authSubPair, KeyFlags.AUTHENTICATION)
        return encodeRings(ringGenerator, masterPair.keyID)
    }

    /** Encodes secret and derived public rings and returns armored bytes plus master key ID. */
    private fun encodeRings(ringGenerator: PGPKeyRingGenerator, masterKeyId: Long): GeneratedKeyRing {
        val secretRing: PGPSecretKeyRing = ringGenerator.generateSecretKeyRing()
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
    private fun addSubkey(ringGenerator: PGPKeyRingGenerator, subPair: org.bouncycastle.openpgp.PGPKeyPair, flags: Int) {
        val hashed = PGPSignatureSubpacketGenerator().apply {
            setKeyFlags(false, flags)
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
