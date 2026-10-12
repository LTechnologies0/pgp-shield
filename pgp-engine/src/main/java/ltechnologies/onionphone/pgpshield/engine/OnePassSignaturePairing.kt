package ltechnologies.onionphone.pgpshield.engine

/**
 * RFC 4880 §5.4: one-pass signature packets are written in reverse order of
 * the trailing signature packets. Pair one-pass index `i` with signature `n-1-i`.
 */
object OnePassSignaturePairing {
    /**
     * @return pairs of (onePassIndex, signatureIndex)
     * @throws PgpException when the lists have different sizes
     */
    fun pairIndices(onePassCount: Int, signatureCount: Int): List<Pair<Int, Int>> {
        if (onePassCount <= 0 || signatureCount <= 0 || onePassCount != signatureCount) {
            throw PgpException("One-pass / signature count mismatch ($onePassCount vs $signatureCount)")
        }
        return (0 until onePassCount).map { i -> i to (signatureCount - 1 - i) }
    }
}
