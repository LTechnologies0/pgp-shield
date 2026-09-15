package ltechnologies.onionphone.pgpshield.util

/**
 * Lightweight heuristics for classifying OpenPGP key material (ASCII armor or binary).
 */

import ltechnologies.onionphone.pgpshield.engine.KeyRingReader

/** Detects whether key bytes / armor contain a secret or public key. */
object ArmoredKeyDetector {
    private val reader = KeyRingReader()

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

    /**
     * Classifies raw key [bytes] (ASCII armor or binary transferable key).
     * Uses armor headers when present; otherwise parses with Bouncy Castle via [KeyRingReader].
     */
    fun isSecretMaterial(bytes: ByteArray): Boolean? {
        val asText = runCatching { String(bytes, Charsets.UTF_8) }.getOrNull()
        if (asText != null) {
            isSecretBlock(asText)?.let { return it }
        }
        return reader.detectSecret(bytes)
    }
}
