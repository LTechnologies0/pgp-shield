package ltechnologies.onionphone.pgpshield.engine

/**
 * Adds subkeys to an existing OpenPGP secret key ring.
 *
 * Generates new subkey material, produces subkey-binding (and optional primary-key-binding)
 * signatures from the master key, and returns an updated armored secret key ring.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Date
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/**
 * Parameters for adding a subkey to an existing secret key ring.
 *
 * @property secretKeyRingArmored ASCII-armored secret key ring to modify.
 * @property passphrase Passphrase to unlock the master secret key.
 * @property subkeyType Algorithm and intended capability of the new subkey.
 * @property rsaBits RSA modulus size when the subkey type is RSA-based.
 */
data class AddSubkeyRequest(
    val secretKeyRingArmored: ByteArray,
    val passphrase: CharArray,
    val subkeyType: SubkeyType,
    val rsaBits: Int = 3072,
)

/**
 * Adds a subkey to an existing secret key ring.
 *
 * Flow mirrors OpenKeychain [PgpKeyOperation.modifySecretKeyRing] step 5
 * (`SaveKeyringParcel.SubkeyAdd` → `createKey` → `generateSubkeyBindingSignature`
 * → `PGPSecretKeyRing.insertSecretKey`).
 *
 * BC note: stock bcpg has no `addSubkeyBindingCertification`; attach the
 * SUBKEY_BINDING certification with [PGPPublicKey.addCertification] on the
 * subkey material (same effect as OpenKeychain's patched helper).
 */
class SubkeyAdder {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Adds a subkey described by [request] and returns the updated armored secret key ring.
     *
     * @throws PgpException if the ring cannot be parsed or the passphrase is wrong.
     */
    fun addSubkey(request: AddSubkeyRequest): ByteArray {
        val secretRing = PGPUtil.getDecoderStream(ByteArrayInputStream(request.secretKeyRingArmored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }
        val masterSecret = secretRing.secretKey
        val masterPublic = masterSecret.publicKey
        val masterPrivate = PgpOperators.extractPrivateKey(masterSecret, request.passphrase)

        val generated = KeyPairFactory.pairForSubkeyType(request.subkeyType, request.rsaBits, Date())
        val masterUseBc = KeyPairFactory.useBcLightweight(masterPublic.algorithm)
        val subUseBc = generated.useBcLightweight
        val flags = subkeyFlags(request.subkeyType)
        val certifiedPublic = generateSubkeyBindingSignature(
            creationTime = Date(),
            masterPublic = masterPublic,
            masterPrivate = masterPrivate,
            subPair = generated.pair,
            flags = flags,
            expirySeconds = 0L,
            masterUseBc = masterUseBc,
            subUseBc = subUseBc,
        )
        val digestCalc = JcaPlatform.digestCalculators.get(
            PgpSecurityConstants.SECRET_KEY_SIGNATURE_CHECKSUM_HASH_ALGO,
        )
        val newSecret = PGPSecretKey(
            generated.pair.privateKey,
            certifiedPublic,
            digestCalc,
            false,
            PgpOperators.secretKeyEncryptor(request.passphrase, subUseBc),
        )
        val updated = PGPSecretKeyRing.insertSecretKey(secretRing, newSecret)
        return ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> updated.encode(armor) }
            out.toByteArray()
        }
    }

    /** Maps [SubkeyType] to OpenPGP key-flags (encrypt, sign, or authenticate). */
    private fun subkeyFlags(type: SubkeyType): Int = when (type) {
        SubkeyType.ENCRYPT_RSA,
        SubkeyType.ENCRYPT_CV25519,
        SubkeyType.ENCRYPT_X448,
        SubkeyType.ENCRYPT_ECDH_P256,
        SubkeyType.ENCRYPT_ECDH_P384,
        SubkeyType.ENCRYPT_ECDH_P521,
        SubkeyType.ENCRYPT_ELGAMAL,
        -> KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE
        SubkeyType.AUTH_RSA,
        SubkeyType.AUTH_ED25519,
        SubkeyType.AUTH_ED448,
        SubkeyType.AUTH_ECDSA_P256,
        SubkeyType.AUTH_ECDSA_P384,
        SubkeyType.AUTH_ECDSA_P521,
        -> KeyFlags.AUTHENTICATION
        else -> KeyFlags.SIGN_DATA
    }

    /**
     * Port of OpenKeychain `PgpKeyOperation.generateSubkeyBindingSignature`.
     * [expirySeconds] is unix seconds; 0 means no expiry (OpenKeychain `SubkeyAdd.expiry = 0L`).
     */
    internal fun generateSubkeyBindingSignature(
        creationTime: Date,
        masterPublic: PGPPublicKey,
        masterPrivate: PGPPrivateKey,
        subPair: org.bouncycastle.openpgp.PGPKeyPair,
        flags: Int,
        expirySeconds: Long,
        masterUseBc: Boolean,
        subUseBc: Boolean,
    ): PGPPublicKey {
        val masterSigGen = PGPSignatureGenerator(
            bindingSignerBuilder(masterPublic.algorithm, masterUseBc),
        )
        val unhashedGen = PGPSignatureSubpacketGenerator()

        // OpenKeychain: primary-key binding only when SIGN_DATA (not AUTH-only subkeys).
        if (flags and KeyFlags.SIGN_DATA != 0) {
            val subSigGen = PGPSignatureGenerator(
                bindingSignerBuilder(subPair.publicKey.algorithm, subUseBc),
            )
            val subHashed = PGPSignatureSubpacketGenerator().apply {
                setSignatureCreationTime(false, creationTime)
            }.generate()
            subSigGen.init(PGPSignature.PRIMARYKEY_BINDING, subPair.privateKey)
            subSigGen.setHashedSubpackets(subHashed)
            val embedded = subSigGen.generateCertification(masterPublic, subPair.publicKey)
            unhashedGen.setEmbeddedSignature(true, embedded)
        }

        val hashed = PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(true, creationTime)
            setKeyFlags(true, flags)
            if (expirySeconds > 0) {
                setKeyExpirationTime(
                    true,
                    expirySeconds - subPair.publicKey.creationTime.time / 1000,
                )
            }
        }.generate()

        masterSigGen.init(PGPSignature.SUBKEY_BINDING, masterPrivate)
        masterSigGen.setHashedSubpackets(hashed)
        masterSigGen.setUnhashedSubpackets(unhashedGen.generate())
        val cert = masterSigGen.generateCertification(masterPublic, subPair.publicKey)
        return PGPPublicKey.addCertification(subPair.publicKey, cert)
    }

    /** Builds a content signer for subkey-binding signatures using the configured hash algorithm. */
    private fun bindingSignerBuilder(algorithm: Int, useBcLightweight: Boolean) =
        PgpOperators.contentSignerBuilder(
            algorithm,
            useBcLightweight,
            PgpSecurityConstants.SECRET_KEY_BINDING_SIGNATURE_HASH_ALGO,
        )
}
