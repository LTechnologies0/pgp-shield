package ltechnologies.onionphone.pgpshield.engine

/**
 * Reads OpenPGP Features / version hints from recipient public key rings.
 */

import java.io.ByteArrayInputStream
import org.bouncycastle.bcpg.sig.Features
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUtil

/** Feature / version capabilities derived from a transferable public key. */
data class RecipientCapabilities(
    val supportsSeipdV2: Boolean,
    val supportsAeadEncryptedData: Boolean,
    val maxKeyVersion: Int,
)

/** Inspects primary-key self-signatures for Features subpackets. */
object PgpRecipientCapabilities {
    fun fromArmoredRing(armored: ByteArray): RecipientCapabilities {
        val primary = primaryKey(armored) ?: return RecipientCapabilities(
            supportsSeipdV2 = false,
            supportsAeadEncryptedData = false,
            maxKeyVersion = 4,
        )
        return fromPrimaryKey(primary)
    }

    fun fromPrimaryKey(primary: PGPPublicKey): RecipientCapabilities {
        val features = findFeatures(primary)
        return RecipientCapabilities(
            supportsSeipdV2 = features?.supportsSEIPDv2() == true,
            supportsAeadEncryptedData = features?.supportsFeature(Features.FEATURE_AEAD_ENCRYPTED_DATA) == true,
            maxKeyVersion = primary.version,
        )
    }

    /**
     * Resolves effective integrity for encryption.
     *
     * When [requested] is [MessageIntegrity.SEIPD_V2_AEAD] and [force] is false, requires every
     * recipient to advertise SEIPDv2. Does **not** silently fall back to MDC (fail closed).
     * Pass [force]=true to emit SEIPDv2 regardless of Features (caller accepts interop risk).
     *
     * @throws PgpException when recipients lack SEIPDv2 and [force] is false.
     */
    fun resolveIntegrity(
        requested: MessageIntegrity,
        recipientRings: List<ByteArray>,
        force: Boolean,
    ): MessageIntegrity {
        if (force || recipientRings.isEmpty()) return requested
        if (requested != MessageIntegrity.SEIPD_V2_AEAD) return requested
        val allSupport = recipientRings.all { fromArmoredRing(it).supportsSeipdV2 }
        if (allSupport) return MessageIntegrity.SEIPD_V2_AEAD
        throw PgpException(
            "Recipients do not advertise SEIPDv2 AEAD; select MDC integrity or update recipient keys",
            SecurityProblem.INSECURE_ALGORITHM,
        )
    }

    /** True when any secret packet still uses classic Iterated+Salted S2K (needs Argon2 upgrade). */
    fun needsAeadSecretUpgrade(secretRingArmored: ByteArray): Boolean =
        !preferAeadSecretProtect(secretRingArmored)

    /** True when the secret ring is v6 or already uses AEAD-style secret protection. */
    fun preferAeadSecretProtect(secretRingArmored: ByteArray): Boolean {
        return runCatching {
            PGPUtil.getDecoderStream(ByteArrayInputStream(secretRingArmored)).use { input ->
                when (val obj = PGPObjectFactory(input, PgpFingerprints.calculator).nextObject()) {
                    is PGPSecretKeyRing -> {
                        val keys = obj.secretKeys.asSequence().toList()
                        keys.any { it.publicKey.version >= 6 } ||
                            keys.any { sk ->
                                runCatching {
                                    val s2k = sk.s2K
                                    s2k != null && s2k.type == org.bouncycastle.bcpg.S2K.ARGON_2
                                }.getOrDefault(false)
                            }
                    }
                    else -> false
                }
            }
        }.getOrDefault(false)
    }

    private fun findFeatures(primary: PGPPublicKey): Features? {
        val direct = primary.signatures?.asSequence()
            ?.filterIsInstance<PGPSignature>()
            ?.mapNotNull { it.hashedSubPackets?.features }
            ?.firstOrNull()
        if (direct != null) return direct
        val userIds = primary.userIDs
        while (userIds.hasNext()) {
            val uid = userIds.next() as? String ?: continue
            val sigs = primary.getSignaturesForID(uid) ?: continue
            while (sigs.hasNext()) {
                val sig = sigs.next() as? PGPSignature ?: continue
                if (sig.keyID == primary.keyID) {
                    sig.hashedSubPackets?.features?.let { return it }
                }
            }
        }
        return null
    }

    private fun primaryKey(armored: ByteArray): PGPPublicKey? =
        runCatching {
            PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
                when (val obj = PGPObjectFactory(input, PgpFingerprints.calculator).nextObject()) {
                    is PGPPublicKeyRing -> obj.publicKey
                    is PGPSecretKeyRing -> obj.publicKey
                    else -> null
                }
            }
        }.getOrNull()
}
