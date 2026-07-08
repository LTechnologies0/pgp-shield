package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP certification trust levels for web-of-trust signatures.
 *
 * Maps user-selectable trust semantics to Bouncy Castle signature type constants.
 * BC 1.79 naming differs slightly from RFC 4880 (see enum KDoc).
 */

import org.bouncycastle.openpgp.PGPSignature

/**
 * OpenPGP certification trust levels. BC 1.79 names differ from the RFC:
 * PERSONA maps to [PGPSignature.NO_CERTIFICATION] (0x11), GENERIC to [PGPSignature.DEFAULT_CERTIFICATION] (0x10).
 */
enum class CertificationType {
    /** Default / unspecified certification (0x10). */
    GENERIC,
    /** Persona-level trust — mapped to NO_CERTIFICATION (0x11) in BC. */
    PERSONA,
    /** Casual certification (0x12). */
    CASUAL,
    /** Positive certification (0x13). */
    POSITIVE,
    ;

    /** Returns the Bouncy Castle [PGPSignature] certification type constant. */
    fun toSignatureType(): Int = when (this) {
        GENERIC -> PGPSignature.DEFAULT_CERTIFICATION
        PERSONA -> PGPSignature.NO_CERTIFICATION
        CASUAL -> PGPSignature.CASUAL_CERTIFICATION
        POSITIVE -> PGPSignature.POSITIVE_CERTIFICATION
    }
}
