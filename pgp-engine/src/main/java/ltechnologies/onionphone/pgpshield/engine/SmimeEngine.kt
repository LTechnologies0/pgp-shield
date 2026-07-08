package ltechnologies.onionphone.pgpshield.engine

/**
 * Placeholder for future S/MIME (CMS) support.
 *
 * PGP Shield targets OpenPGP; this class reserves the API surface for PKCS#7/CMS
 * encrypt and decrypt when bcpkix integration is added.
 */

/**
 * S/MIME engine stub. All operations throw [PgpException] until CMS support is implemented.
 */
class SmimeEngine {
    /** Encrypts plaintext with S/MIME (not yet implemented). */
    fun encrypt(@Suppress("UNUSED_PARAMETER") plaintext: ByteArray): ByteArray =
        throw PgpException("S/MIME encrypt not implemented (CMS support planned)")

    /** Decrypts S/MIME ciphertext (not yet implemented). */
    fun decrypt(@Suppress("UNUSED_PARAMETER") ciphertext: ByteArray): ByteArray =
        throw PgpException("S/MIME decrypt not implemented (CMS support planned)")
}
