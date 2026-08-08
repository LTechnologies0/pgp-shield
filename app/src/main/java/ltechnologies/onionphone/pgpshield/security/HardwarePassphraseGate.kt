package ltechnologies.onionphone.pgpshield.security

import androidx.fragment.app.FragmentActivity
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.pgpshield.data.security.HardwarePassphraseVault
import ltechnologies.onionphone.pgpshield.data.security.PassphraseWrappingKeyInfo
import ltechnologies.onionphone.pgpshield.data.security.SensitiveMemory

/**
 * Orchestrates biometric/PIN unlock around [HardwarePassphraseVault] CryptoObject ops.
 */
@Singleton
class HardwarePassphraseGate @Inject constructor(
    private val vault: HardwarePassphraseVault,
    private val authenticator: HardwarePassphraseAuthenticator,
) {
    fun isAvailable(): Boolean = vault.isAvailable()

    fun inspectWrappingKey(): PassphraseWrappingKeyInfo? = vault.inspectWrappingKey()

    fun generatePassphrase(): CharArray = vault.generatePassphrase()

    /**
     * Seals [passphrase] for [keyId] after PIN/biometric authentication.
     * Verifies the wrapping key is inside secure hardware.
     */
    suspend fun sealAfterAuth(
        activity: FragmentActivity,
        keyId: Long,
        passphrase: CharArray,
    ): PassphraseWrappingKeyInfo {
        val cipher = withContext(Dispatchers.IO) { vault.prepareEncryptCipher() }
        val unlocked = authenticator.authenticateCipher(
            activity,
            cipher,
            title = "Protéger la passphrase",
            subtitle = "PIN ou biométrie pour sceller la passphrase dans StrongBox/TEE",
        )
        return withContext(Dispatchers.IO) {
            vault.sealPassphrase(keyId, passphrase, unlocked)
            val info = vault.ensureWrappingKey()
            require(info.insideSecureHardware) {
                "La clé de wrapping n'est pas dans l'enclave sécurisée"
            }
            require(info.userAuthenticationRequired) {
                "La clé de wrapping doit exiger l'authentification utilisateur"
            }
            info
        }
    }

    /**
     * Unlocks the hardware-managed passphrase for [keyId] after PIN/biometric.
     * Caller must wipe the returned [CharArray].
     */
    suspend fun unlockAfterAuth(
        activity: FragmentActivity,
        keyId: Long,
    ): CharArray {
        val cipher = withContext(Dispatchers.IO) { vault.prepareDecryptCipher(keyId) }
        val unlocked = authenticator.authenticateCipher(
            activity,
            cipher,
            title = "Déverrouiller la clé privée",
            subtitle = "PIN ou biométrie — la passphrase ne quitte pas l'enclave sans auth",
        )
        return withContext(Dispatchers.IO) {
            vault.unlockPassphrase(keyId, unlocked)
        }
    }

    fun delete(keyId: Long) = vault.deletePassphrase(keyId)

    /** Wipes [buffers] — thin wrapper for call sites outside the data module. */
    fun wipe(vararg buffers: CharArray?) = SensitiveMemory.wipe(*buffers)
}
