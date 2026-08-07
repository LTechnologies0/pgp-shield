package ltechnologies.onionphone.pgpshield.data.security

/**
 * Gate checked before reading secret key material.
 * App layer binds this to biometric / device-credential unlock.
 */
fun interface VaultAccessPolicy {
    /** Throws if secrets must not be read (app locked). */
    fun assertSecretsAccessible()
}

/** No-op policy for unit tests and early process bootstrap. */
object PermissiveVaultAccessPolicy : VaultAccessPolicy {
    override fun assertSecretsAccessible() = Unit
}
