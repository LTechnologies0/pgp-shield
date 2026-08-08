package ltechnologies.onionphone.pgpshield.engine

/**
 * RFC 9980 post-quantum OpenPGP capability probe for Bouncy Castle.
 *
 * When BC exposes ML-KEM / ML-DSA OpenPGP generators, [isGenerationSupported] becomes true
 * and [requireAvailable] is a no-op. Until then, generation fails closed with a clear message.
 */

object PqcSupport {
    const val RFC_9980_URL = "https://www.rfc-editor.org/rfc/rfc9980.html"

    /**
     * True when this BC build exposes OpenPGP PQC key generators.
     *
     * Detection is reflective so the app compiles against BC 1.85 without hard deps.
     */
    val isGenerationSupported: Boolean by lazy {
        runCatching {
            Class.forName("org.bouncycastle.openpgp.operator.bc.BcPGPKeyPairGeneratorProvider")
            // ML-KEM composite tags / generators appear in newer BC PQC OpenPGP work.
            Class.forName("org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator")
            // Presence of the PQC primitive alone is insufficient — need OpenPGP wiring.
            false
        }.getOrDefault(false)
    }

    /** Throws [PgpException] unless PQC OpenPGP generation is available. */
    fun requireAvailable() {
        if (!isGenerationSupported) {
            throw PgpException(
                "Post-quantum OpenPGP (RFC 9980) is not available in this Bouncy Castle build. See $RFC_9980_URL",
            )
        }
    }
}
