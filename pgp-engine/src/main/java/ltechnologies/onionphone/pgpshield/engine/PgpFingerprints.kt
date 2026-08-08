package ltechnologies.onionphone.pgpshield.engine

/**
 * Shared OpenPGP fingerprint calculator.
 *
 * Creating a new calculator per engine class was wasteful; BC's lightweight
 * implementation is process-wide reusable and thread-safe for fingerprinting.
 */

import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator

/** Process-wide fingerprint calculator for packet parsing. */
object PgpFingerprints {
    val calculator: KeyFingerPrintCalculator = BcKeyFingerprintCalculator()
}
