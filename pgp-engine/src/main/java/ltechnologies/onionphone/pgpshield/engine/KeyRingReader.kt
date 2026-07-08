package ltechnologies.onionphone.pgpshield.engine

/**
 * Parses OpenPGP key rings into structured [ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo].
 *
 * Reads public and secret key rings from streams or armored strings and extracts
 * user IDs, subkey metadata, fingerprints, and capability flags.
 */

import ltechnologies.onionphone.pgpshield.engine.model.KeyRingInfo
import ltechnologies.onionphone.pgpshield.engine.model.SubkeyInfo
import ltechnologies.onionphone.pgpshield.engine.model.UserIdInfo
import java.io.InputStream
import java.time.Instant
import org.bouncycastle.bcpg.sig.KeyFlags
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator

/** Reads OpenPGP key rings and maps them to [KeyRingInfo]. */
class KeyRingReader {
    private val fingerprintCalculator = JcaKeyFingerprintCalculator()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /** Parses a public key ring from a binary or armored [input] stream. */
    fun readPublicKeyRing(input: InputStream): KeyRingInfo {
        val decoder = PGPUtil.getDecoderStream(input)
        val objectFactory = org.bouncycastle.openpgp.PGPObjectFactory(decoder, fingerprintCalculator)
        val ring = objectFactory.nextObject() as? PGPPublicKeyRing
            ?: throw PgpException("No public key ring found")
        return toInfo(ring.publicKey, publicKeys(ring), isSecret = false)
    }

    /** Parses a secret key ring from a binary or armored [input] stream. */
    fun readSecretKeyRing(input: InputStream): KeyRingInfo {
        val decoder = PGPUtil.getDecoderStream(input)
        val objectFactory = org.bouncycastle.openpgp.PGPObjectFactory(decoder, fingerprintCalculator)
        val ring = objectFactory.nextObject() as? PGPSecretKeyRing
            ?: throw PgpException("No secret key ring found")
        val keys = ArrayList<PGPPublicKey>()
        val iter = ring.secretKeys
        while (iter.hasNext()) {
            keys.add(iter.next().publicKey)
        }
        return toInfo(ring.publicKey, keys, isSecret = true)
    }

    /**
     * Parses an armored key ring string.
     *
     * @param secret When `true`, expect a secret key ring; otherwise public.
     */
    fun readArmoredKeyRing(armored: String, secret: Boolean): KeyRingInfo =
        armored.byteInputStream(Charsets.UTF_8).use { input ->
            if (secret) readSecretKeyRing(input) else readPublicKeyRing(input)
        }

    private fun publicKeys(ring: PGPPublicKeyRing): List<PGPPublicKey> {
        val keys = ArrayList<PGPPublicKey>()
        val iter = ring.publicKeys
        while (iter.hasNext()) {
            keys.add(iter.next())
        }
        return keys
    }

    /** Builds [KeyRingInfo] from the master key and full key list. */
    private fun toInfo(master: PGPPublicKey, keys: List<PGPPublicKey>, isSecret: Boolean): KeyRingInfo {
        val userIds = master.userIDs.asSequence().mapIndexed { index, id ->
            UserIdInfo(id.toString(), index == 0)
        }.toList()

        val subkeys = keys.map { key ->
            SubkeyInfo(
                keyId = key.keyID,
                fingerprint = formatFingerprint(key.fingerprint),
                algorithm = key.algorithm,
                creationTime = Instant.ofEpochMilli(key.creationTime.time),
                expirationTime = key.validSeconds.takeIf { it > 0 }?.let {
                    Instant.ofEpochMilli(key.creationTime.time + it * 1000L)
                },
                isRevoked = key.isRevoked,
                flags = readKeyFlags(key),
            )
        }

        return KeyRingInfo(
            masterKeyId = master.keyID,
            fingerprint = formatFingerprint(master.fingerprint),
            userIds = userIds,
            subkeys = subkeys,
            isSecret = isSecret,
            isRevoked = master.isRevoked,
        )
    }

    /** Reads key-flags from self-certifications, with sensible defaults by key role. */
    private fun readKeyFlags(key: PGPPublicKey): Int {
        var flags = 0
        val sigs = key.signatures
        while (sigs.hasNext()) {
            val sig = sigs.next() as PGPSignature
            val type = sig.signatureType
            if (type != PGPSignature.POSITIVE_CERTIFICATION &&
                type != PGPSignature.SUBKEY_BINDING &&
                type != PGPSignature.DIRECT_KEY
            ) {
                continue
            }
            val hashed = sig.hashedSubPackets ?: continue
            val packetFlags = hashed.getKeyFlags() ?: continue
            flags = flags or packetFlags
        }
        if (flags == 0) {
            if (key.isEncryptionKey) {
                flags = flags or KeyFlags.ENCRYPT_COMMS or KeyFlags.ENCRYPT_STORAGE
            }
            if (key.isMasterKey) {
                flags = flags or KeyFlags.CERTIFY_OTHER or KeyFlags.SIGN_DATA
            }
        }
        return flags
    }

    companion object {
        /** Formats a raw fingerprint byte array as space-separated uppercase hex. */
        fun formatFingerprint(bytes: ByteArray): String =
            bytes.joinToString(" ") { "%02X".format(it) }

        /**
         * Derives the 64-bit key ID from a hex fingerprint string.
         *
         * @throws IllegalArgumentException if the fingerprint is too short.
         */
        fun keyIdFromFingerprintHex(hex: String): Long {
            val clean = hex.replace(" ", "").uppercase()
            require(clean.length >= 16) { "Fingerprint too short" }
            return clean.takeLast(16).toLong(16)
        }
    }
}
