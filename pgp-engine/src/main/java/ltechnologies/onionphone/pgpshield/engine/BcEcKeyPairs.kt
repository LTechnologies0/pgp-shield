package ltechnologies.onionphone.pgpshield.engine

/**
 * NIST P-curve key generation via Bouncy Castle lightweight API.
 *
 * Produces `BcPGPKeyPair` instances for ECDSA signing and ECDH encryption subkeys
 * on P-256, P-384, and P-521 curves.
 */

import java.util.Date
import org.bouncycastle.asn1.nist.NISTNamedCurves
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECNamedDomainParameters
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair

/** BC lightweight ECDSA and ECDH key pairs on NIST curves. */
object BcEcKeyPairs {
    /** ECDSA signing key on [curve]. */
    fun ecdsa(curve: EccCurve, date: Date): BcPGPKeyPair =
        ecPair(curve.nistName, PGPPublicKey.ECDSA, date)

    /** ECDH encryption subkey on [curve]. */
    fun ecdh(curve: EccCurve, date: Date): BcPGPKeyPair =
        ecPair(curve.nistName, PGPPublicKey.ECDH, date)

    private fun ecPair(nistName: String, pgpTag: Int, date: Date): BcPGPKeyPair {
        val x9 = NISTNamedCurves.getByName(nistName)
            ?: throw PgpException("Unknown curve $nistName")
        val oid = NISTNamedCurves.getOID(nistName)
        val gen = ECKeyPairGenerator()
        gen.init(
            ECKeyGenerationParameters(
                ECNamedDomainParameters(oid, x9.curve, x9.g, x9.n),
                SecureRandomProvider.secureRandom,
            ),
        )
        return BcPGPKeyPair(pgpTag, gen.generateKeyPair(), date)
    }
}
