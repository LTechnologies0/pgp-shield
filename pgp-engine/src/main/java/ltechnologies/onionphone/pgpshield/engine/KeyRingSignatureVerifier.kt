package ltechnologies.onionphone.pgpshield.engine

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature

/**
 * Verifies user-id self-certifications and subkey-binding signatures on import.
 */
object KeyRingSignatureVerifier {
    fun verify(ring: PGPPublicKeyRing) {
        val master = ring.publicKey
        verifyUserIdSelfSigs(master)
        val keys = ring.publicKeys
        if (!keys.hasNext()) throw PgpException("Empty public key ring")
        keys.next()
        while (keys.hasNext()) {
            verifySubkeyBinding(master, keys.next())
        }
    }

    fun verify(ring: PGPSecretKeyRing) {
        val pubs = ArrayList<PGPPublicKey>()
        val iter = ring.publicKeys
        while (iter.hasNext()) pubs.add(iter.next())
        if (pubs.isEmpty()) throw PgpException("Empty secret key ring")
        verify(PGPPublicKeyRing(pubs))
    }

    private fun verifyUserIdSelfSigs(master: PGPPublicKey) {
        val userIds = master.userIDs
        var sawUid = false
        while (userIds.hasNext()) {
            sawUid = true
            val uid = userIds.next().toString()
            if (!hasValidSelfCert(master, uid)) {
                throw PgpException("Missing valid user-id self-signature")
            }
        }
        if (!sawUid) {
            throw PgpException("Key ring has no user id")
        }
    }

    private fun hasValidSelfCert(master: PGPPublicKey, userId: String): Boolean {
        val sigs = master.getSignaturesForID(userId) ?: return false
        while (sigs.hasNext()) {
            val sig = sigs.next() as PGPSignature
            if (sig.keyID != master.keyID) continue
            if (sig.signatureType != PGPSignature.DEFAULT_CERTIFICATION &&
                sig.signatureType != PGPSignature.NO_CERTIFICATION &&
                sig.signatureType != PGPSignature.CASUAL_CERTIFICATION &&
                sig.signatureType != PGPSignature.POSITIVE_CERTIFICATION
            ) {
                continue
            }
            if (verifyCertification(sig, master, userId)) return true
        }
        return false
    }

    private fun verifySubkeyBinding(master: PGPPublicKey, subkey: PGPPublicKey) {
        val sigs = subkey.signatures
        while (sigs.hasNext()) {
            val sig = sigs.next() as PGPSignature
            if (sig.signatureType != PGPSignature.SUBKEY_BINDING) continue
            if (sig.keyID != master.keyID) continue
            if (verifySubkeyBindingSig(sig, master, subkey)) return
        }
        throw PgpException("Missing valid subkey-binding signature")
    }

    private fun verifyCertification(sig: PGPSignature, master: PGPPublicKey, userId: String): Boolean {
        return tryInitAnd { useBc ->
            sig.init(PgpOperators.contentVerifierProvider(useBc), master)
            sig.verifyCertification(userId, master)
        }
    }

    private fun verifySubkeyBindingSig(sig: PGPSignature, master: PGPPublicKey, subkey: PGPPublicKey): Boolean {
        return tryInitAnd { useBc ->
            sig.init(PgpOperators.contentVerifierProvider(useBc), master)
            sig.verifyCertification(master, subkey)
        }
    }

    private fun tryInitAnd(block: (Boolean) -> Boolean): Boolean {
        val useBc = true
        return try {
            block(useBc)
        } catch (_: Exception) {
            try {
                block(!useBc)
            } catch (_: Exception) {
                false
            }
        }
    }
}
