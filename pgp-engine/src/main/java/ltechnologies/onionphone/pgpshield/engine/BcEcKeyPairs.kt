package ltechnologies.onionphone.pgpshield.engine

/**
 * Named elliptic-curve key generation via Bouncy Castle lightweight API.
 *
 * Produces `BcPGPKeyPair` instances for ECDSA signing and ECDH encryption subkeys
 * on NIST P-curves and TeleTrusT Brainpool r1 curves (OpenPGP / RFC 9580).
 */

import java.util.Date
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.nist.NISTNamedCurves
import org.bouncycastle.asn1.teletrust.TeleTrusTNamedCurves
import org.bouncycastle.asn1.x9.X9ECParameters
import org.bouncycastle.crypto.generators.ECKeyPairGenerator
import org.bouncycastle.crypto.params.ECKeyGenerationParameters
import org.bouncycastle.crypto.params.ECNamedDomainParameters
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair

/** BC lightweight ECDSA and ECDH key pairs on NIST and Brainpool curves. */
object BcEcKeyPairs {
    /** ECDSA signing key on [curve]. */
    fun ecdsa(curve: EccCurve, date: Date): BcPGPKeyPair =
        ecPair(curve, PGPPublicKey.ECDSA, date)

    /** ECDH encryption subkey on [curve]. */
    fun ecdh(curve: EccCurve, date: Date): BcPGPKeyPair =
        ecPair(curve, PGPPublicKey.ECDH, date)

    private fun ecPair(curve: EccCurve, pgpTag: Int, date: Date): BcPGPKeyPair {
        val (oid, x9) = curveParameters(curve)
        val gen = ECKeyPairGenerator()
        gen.init(
            ECKeyGenerationParameters(
                ECNamedDomainParameters(oid, x9.curve, x9.g, x9.n),
                SecureRandomProvider.secureRandom,
            ),
        )
        return BcPGPKeyPair(pgpTag, gen.generateKeyPair(), date)
    }

    private fun curveParameters(curve: EccCurve): Pair<ASN1ObjectIdentifier, X9ECParameters> {
        val x9: X9ECParameters?
        val oid: ASN1ObjectIdentifier?
        when (curve.family) {
            EccCurveFamily.NIST -> {
                x9 = NISTNamedCurves.getByName(curve.bcName)
                oid = NISTNamedCurves.getOID(curve.bcName)
            }
            EccCurveFamily.BRAINPOOL -> {
                x9 = TeleTrusTNamedCurves.getByName(curve.bcName)
                oid = TeleTrusTNamedCurves.getOID(curve.bcName)
            }
        }
        if (x9 == null || oid == null) {
            throw PgpException("Unknown curve ${curve.bcName}")
        }
        return oid to x9
    }
}
