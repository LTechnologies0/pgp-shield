package ltechnologies.onionphone.pgpshield.util

/**
 * Lightweight heuristics for classifying ASCII-armored OpenPGP key blocks.
 */

/** Detects whether an armored block contains a secret or public key. */
object ArmoredKeyDetector {
    /**
     * Classifies an armored block.
     *
     * @return `true` for a secret/private key block, `false` for a public key
     *   block, or `null` when no recognizable PGP header is present.
     */
    fun isSecretBlock(armored: String): Boolean? = when {
        armored.contains("BEGIN PGP PRIVATE KEY BLOCK") ||
            armored.contains("BEGIN PGP SECRET KEY BLOCK") -> true
        armored.contains("BEGIN PGP PUBLIC KEY BLOCK") -> false
        else -> null
    }

    /** Produces a user-facing label describing the detected block type. */
    fun label(armored: String): String = when (isSecretBlock(armored)) {
        true -> "Secret key detected"
        false -> "Public key detected"
        null -> "Paste a -----BEGIN PGP...----- block"
    }
}
