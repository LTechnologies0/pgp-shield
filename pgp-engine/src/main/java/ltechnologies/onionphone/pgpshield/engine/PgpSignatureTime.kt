package ltechnologies.onionphone.pgpshield.engine

import java.util.Date
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPSignature

/**
 * Key-validity checks evaluated at signature creation time (not "now").
 */
object PgpSignatureTime {
    /**
     * True when [key] existed and was unexpired at [at].
     *
     * Revocation signatures created at or before [at] make the key invalid.
     */
    fun keyValidAt(key: PGPPublicKey, at: Date?): Boolean {
        val whenMs = at?.time ?: return !key.isRevoked
        if (key.creationTime != null && key.creationTime.time > whenMs) return false
        val validSeconds = key.validSeconds
        if (validSeconds > 0) {
            val expiryMs = key.creationTime.time + validSeconds * 1000L
            if (whenMs > expiryMs) return false
        }
        val revocations = key.getSignaturesOfType(PGPSignature.KEY_REVOCATION)
        while (revocations.hasNext()) {
            val rev = revocations.next() as PGPSignature
            val created = rev.creationTime?.time ?: continue
            if (created <= whenMs) return false
        }
        if (!key.isMasterKey) {
            val subRev = key.getSignaturesOfType(PGPSignature.SUBKEY_REVOCATION)
            while (subRev.hasNext()) {
                val rev = subRev.next() as PGPSignature
                val created = rev.creationTime?.time ?: continue
                if (created <= whenMs) return false
            }
        }
        return true
    }
}
