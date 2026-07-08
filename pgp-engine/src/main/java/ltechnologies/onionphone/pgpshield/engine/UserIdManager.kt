package ltechnologies.onionphone.pgpshield.engine

/**
 * User ID management on OpenPGP master keys.
 *
 * Supports adding user IDs, revoking user ID certifications, and changing the
 * primary user ID on an existing secret key ring.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.util.Date
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.bcpg.sig.RevocationReasonTags
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
 * Parameters for a user ID edit operation on a secret key ring.
 *
 * @property secretKeyRingArmored ASCII-armored secret key ring to modify.
 * @property passphrase Passphrase to unlock the master secret key.
 * @property userId User ID string to add, revoke, or mark as primary.
 */
data class UserIdEditRequest(
    val secretKeyRingArmored: ByteArray,
    val passphrase: CharArray,
    val userId: String,
)

/** Adds, revokes, and reorders user IDs on OpenPGP master keys. */
class UserIdManager {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Adds a new user ID certification to the master key.
     *
     * @return Updated armored secret key ring.
     * @throws IllegalArgumentException if [UserIdEditRequest.userId] is blank.
     */
    fun addUserId(request: UserIdEditRequest): ByteArray {
        require(request.userId.isNotBlank()) { "User ID must not be blank" }
        return updateMaster(request) { publicKey, privateKey, useBc ->
            val cert = userIdCert(publicKey, privateKey, request.userId, primary = false, useBc)
            PGPPublicKey.addCertification(publicKey, request.userId, cert)
        }
    }

    /**
     * Revokes an existing user ID certification on the master key.
     *
     * @throws IllegalArgumentException if the user ID is not present on the key.
     */
    fun revokeUserId(request: UserIdEditRequest): ByteArray {
        return updateMaster(request) { publicKey, privateKey, useBc ->
            require(userIdExists(publicKey, request.userId)) { "User ID not found" }
            val now = Date()
            val hashed = PGPSignatureSubpacketGenerator().apply {
                setRevocationReason(false, RevocationReasonTags.NO_REASON, "")
                setSignatureCreationTime(true, now)
            }.generate()
            val sigGen = PGPSignatureGenerator(
                PgpOperators.contentSignerBuilder(publicKey.algorithm, useBc),
            )
            sigGen.setHashedSubpackets(hashed)
            sigGen.init(PGPSignature.CERTIFICATION_REVOCATION, privateKey)
            val rev = sigGen.generateCertification(request.userId, publicKey)
            PGPPublicKey.addCertification(publicKey, request.userId, rev)
        }
    }

    /**
     * Marks [UserIdEditRequest.userId] as the primary user ID, re-certifying all IDs.
     *
     * @throws IllegalArgumentException if the user ID is blank or not found.
     */
    fun setPrimaryUserId(request: UserIdEditRequest): ByteArray {
        require(request.userId.isNotBlank()) { "User ID must not be blank" }
        return updateMaster(request) { publicKey, privateKey, useBc ->
            var updated = publicKey
            val flags = masterKeyFlags(publicKey)
            val ids = publicKey.userIDs
            while (ids.hasNext()) {
                val uid = ids.next().toString()
                updated = stripSelfCerts(updated, uid)
                val cert = userIdCert(updated, privateKey, uid, uid == request.userId, useBc, flags)
                updated = PGPPublicKey.addCertification(updated, uid, cert)
            }
            require(userIdExists(updated, request.userId)) { "User ID not found" }
            updated
        }
    }

    /** Applies [transform] to the master public key and rebuilds the armored secret ring. */
    private fun updateMaster(
        request: UserIdEditRequest,
        transform: (PGPPublicKey, PGPPrivateKey, Boolean) -> PGPPublicKey,
    ): ByteArray {
        val secretRing = loadSecretRing(request.secretKeyRingArmored)
        val masterSecret = secretRing.secretKey
        val useBc = PgpOperators.useBcForPublicKey(masterSecret.publicKey)
        val privateKey = PgpOperators.extractPrivateKey(masterSecret, request.passphrase)
        val updatedPublic = transform(masterSecret.publicKey, privateKey, useBc)
        val newMaster = PGPSecretKey.replacePublicKey(masterSecret, updatedPublic)
        return armorSecretRing(replaceMasterSecretKey(secretRing, newMaster))
    }

    /** Creates a positive (or primary) user ID certification signature. */
    private fun userIdCert(
        publicKey: PGPPublicKey,
        privateKey: PGPPrivateKey,
        userId: String,
        primary: Boolean,
        useBc: Boolean,
        flags: Int = masterKeyFlags(publicKey),
    ): PGPSignature {
        val now = Date()
        val hashed = PGPSignatureSubpacketGenerator().apply {
            setSignatureCreationTime(true, now)
            setKeyFlags(true, flags)
            setPrimaryUserID(false, primary)
        }.generate()
        val sigGen = PGPSignatureGenerator(
            PgpOperators.contentSignerBuilder(publicKey.algorithm, useBc),
        )
        sigGen.setHashedSubpackets(hashed)
        sigGen.init(PGPSignature.POSITIVE_CERTIFICATION, privateKey)
        return sigGen.generateCertification(userId, publicKey)
    }

    /** Removes self-signatures on [userId] before re-certifying (used when changing primary). */
    private fun stripSelfCerts(publicKey: PGPPublicKey, userId: String): PGPPublicKey {
        var key = publicKey
        val sigs = publicKey.getSignaturesForID(userId) ?: return key
        while (sigs.hasNext()) {
            val sig = sigs.next()
            if (sig.keyID != publicKey.keyID) continue
            when (sig.signatureType) {
                PGPSignature.CERTIFICATION_REVOCATION,
                PGPSignature.NO_CERTIFICATION,
                PGPSignature.CASUAL_CERTIFICATION,
                PGPSignature.POSITIVE_CERTIFICATION,
                PGPSignature.DEFAULT_CERTIFICATION,
                -> key = PGPPublicKey.removeCertification(key, userId, sig) ?: key
            }
        }
        return key
    }

    /** Aggregates key-flags from self-certifications on the master key. */
    private fun masterKeyFlags(key: PGPPublicKey): Int {
        var flags = 0
        val sigs = key.signatures
        while (sigs.hasNext()) {
            val sig = sigs.next()
            if (sig.signatureType != PGPSignature.POSITIVE_CERTIFICATION &&
                sig.signatureType != PGPSignature.SUBKEY_BINDING &&
                sig.signatureType != PGPSignature.DIRECT_KEY
            ) {
                continue
            }
            val hashed = sig.hashedSubPackets ?: continue
            flags = flags or (hashed.getKeyFlags() ?: 0)
        }
        if (flags == 0 && key.isMasterKey) {
            flags = KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA
        }
        return flags
    }

    private fun userIdExists(key: PGPPublicKey, userId: String): Boolean {
        val ids = key.userIDs
        while (ids.hasNext()) {
            if (ids.next().toString() == userId) return true
        }
        return false
    }

    private fun loadSecretRing(armored: ByteArray): PGPSecretKeyRing =
        PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            PGPObjectFactory(input, fingerprintCalculator).nextObject() as PGPSecretKeyRing
        }

    private fun replaceMasterSecretKey(ring: PGPSecretKeyRing, newMaster: PGPSecretKey): PGPSecretKeyRing {
        val keys = ArrayList<PGPSecretKey>()
        val iter = ring.secretKeys
        var first = true
        while (iter.hasNext()) {
            keys.add(if (first) newMaster else iter.next())
            first = false
        }
        return PGPSecretKeyRing(keys)
    }

    private fun armorSecretRing(ring: PGPSecretKeyRing): ByteArray =
        ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> ring.encode(armor) }
            out.toByteArray()
        }
}
