package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenKeychain-compatible public-key minimization for Autocrypt / GET_KEY.
 *
 * Keeps a single matching user ID (and its certifications) on the master key;
 * strips other UIDs. Subkeys are preserved.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil

/** Minimizes ASCII-armored public key rings for mail Autocrypt headers. */
object KeyRingMinimizer {
    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Returns an armored public ring with only [keepUserId] (email or full UID) retained.
     * When [keepUserId] is null/blank, keeps the first / primary user ID only.
     */
    fun minimizePublicArmored(armored: ByteArray, keepUserId: String?): ByteArray {
        val ring = PGPUtil.getDecoderStream(ByteArrayInputStream(armored)).use { input ->
            PGPObjectFactory(input, PgpFingerprints.calculator).nextObject() as? PGPPublicKeyRing
        } ?: return armored

        var master = ring.publicKey
        val uids = master.userIDs.asSequence().toList()
        if (uids.size <= 1) return armored

        val wanted = normalizeEmail(keepUserId)
        val keepExact = keepUserId?.trim()?.takeIf { it.isNotEmpty() }
        // Prefer explicit keep target; otherwise retain the first UID (Autocrypt-style shrink).
        val fallbackKeep = uids.first()

        for (uid in uids) {
            val keep = when {
                wanted != null -> normalizeEmail(uid) == wanted ||
                    (keepExact != null && uid.equals(keepExact, ignoreCase = true))
                keepExact != null -> uid.equals(keepExact, ignoreCase = true)
                else -> uid == fallbackKeep
            }
            if (!keep) {
                master = PGPPublicKey.removeCertification(master, uid) ?: master
            }
        }
        val minimized = replaceMasterKeyInRing(ring, master)
        return armor(minimized.encoded)
    }

    private fun normalizeEmail(raw: String?): String? {
        if (raw.isNullOrBlank()) return null
        val trimmed = raw.trim()
        val fromAngles = trimmed.substringAfter('<', missingDelimiterValue = "")
            .substringBefore('>', missingDelimiterValue = "")
            .trim()
        val email = (fromAngles.ifBlank { trimmed }).lowercase()
        return email.takeIf { it.contains('@') }
    }

    private fun armor(data: ByteArray): ByteArray =
        ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> armor.write(data) }
            out.toByteArray()
        }
}
