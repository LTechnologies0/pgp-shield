package ltechnologies.onionphone.pgpshield.engine

/**
 * Message-level OpenPGP options shared by encrypt/decrypt paths.
 */

import org.bouncycastle.bcpg.CompressionAlgorithmTags

/** Integrity protection for encrypted OpenPGP messages. */
enum class MessageIntegrity {
    /** Classic SEIPDv1 with Modification Detection Code. */
    MDC,
    /** RFC 9580 SEIPDv2 AEAD (v6 style session/AEAD packets). */
    SEIPD_V2_AEAD,
    /** LibrePGP / GnuPG v5-style AEAD Encrypted Data (distinct from SEIPDv2). */
    LIBREPGP_V5_AEAD,
}

/** Optional compression applied before encryption. */
enum class MessageCompression(val tag: Int) {
    NONE(CompressionAlgorithmTags.UNCOMPRESSED),
    ZIP(CompressionAlgorithmTags.ZIP),
    ZLIB(CompressionAlgorithmTags.ZLIB),
    BZIP2(CompressionAlgorithmTags.BZIP2),
}

/** OpenPGP key packet format for generation. */
enum class KeyFormat {
    /** Classic v4 rings (OpenKeychain / GnuPG default interop). */
    V4,
    /** RFC 9580 v6 keys via BC OpenPGPKeyGenerator. */
    V6,
}

/**
 * High-level interop profile selecting defaults for message integrity and Features.
 *
 * Used by Settings / Crypto UI; engine APIs still accept explicit [MessageIntegrity].
 */
enum class InteropProfile {
    /** Prefer RFC 9580 SEIPDv2 AEAD; never silently downgrade to MDC. */
    RFC9580_MODERN,
    /** Prefer LibrePGP v5 AEAD for GnuPG-oriented interop. */
    LIBREPGP_GNUPG,
    /** Always MDC SEIPDv1 for maximum legacy reach. */
    LEGACY_MDC,
    ;

    /** Default [MessageIntegrity] for encrypt when this profile is active. */
    fun defaultIntegrity(): MessageIntegrity = when (this) {
        RFC9580_MODERN -> MessageIntegrity.SEIPD_V2_AEAD
        LIBREPGP_GNUPG -> MessageIntegrity.LIBREPGP_V5_AEAD
        LEGACY_MDC -> MessageIntegrity.MDC
    }

    companion object {
        fun fromName(name: String): InteropProfile =
            entries.find { it.name == name } ?: RFC9580_MODERN
    }
}
