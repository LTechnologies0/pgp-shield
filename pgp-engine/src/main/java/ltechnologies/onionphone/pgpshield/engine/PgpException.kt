package ltechnologies.onionphone.pgpshield.engine

/**
 * Engine-wide exception types for cryptographic and policy failures.
 *
 * [PgpException] carries an optional [SecurityProblem] classification for
 * callers that need structured error handling (e.g. UI warnings).
 */

/**
 * General PGP engine failure.
 *
 * @property securityProblem Optional structured security classification.
 */
class PgpException(
    message: String,
    val securityProblem: SecurityProblem? = null,
    cause: Throwable? = null,
) : Exception(message, cause)

/**
 * Structured security problem detected during verify or decrypt operations.
 */
enum class SecurityProblem {
    /** Message lacks integrity protection (no MDC / SEIP). */
    UNSIGNED,
    /** Signer or recipient key not found in provided key material. */
    UNKNOWN_KEY,
    /** Key or message uses a disallowed algorithm. */
    INSECURE_ALGORITHM,
    /** Modification detection code (MDC) verification failed. */
    MDC_FAILURE,
    /** Key or subkey has been revoked. */
    REVOKED_KEY,
    /** Key or subkey has expired. */
    EXPIRED_KEY,
}
