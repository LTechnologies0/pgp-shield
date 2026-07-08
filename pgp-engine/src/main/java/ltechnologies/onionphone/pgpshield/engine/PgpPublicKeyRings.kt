package ltechnologies.onionphone.pgpshield.engine

/**
 * Internal helpers for manipulating OpenPGP public key rings.
 *
 * Shared by key certification and revocation application when replacing the master key.
 */

import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing

/**
 * Replaces the master public key in [ring] while preserving subkey order.
 *
 * @param ring Existing public key ring.
 * @param master Updated master [PGPPublicKey] (e.g. after certification or revocation).
 */
internal fun replaceMasterKeyInRing(ring: PGPPublicKeyRing, master: PGPPublicKey): PGPPublicKeyRing {
    val keys = ArrayList<PGPPublicKey>()
    val iter = ring.publicKeys
    var first = true
    while (iter.hasNext()) {
        val key = iter.next()
        keys.add(if (first) master else key)
        first = false
    }
    return PGPPublicKeyRing(keys)
}
