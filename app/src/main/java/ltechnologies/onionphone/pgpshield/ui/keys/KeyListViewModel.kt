package ltechnologies.onionphone.pgpshield.ui.keys

/**
 * State holder and operations for the key list and key management flows
 * (create, import, delete, revoke, subkeys, passphrase, certification, keyserver).
 */

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.ImportGuard
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeySummary
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.engine.AlgorithmLabels
import ltechnologies.onionphone.pgpshield.engine.KeyAlgorithmType
import ltechnologies.onionphone.pgpshield.engine.KeyRingExporter
import ltechnologies.onionphone.pgpshield.engine.SubkeyType
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.flow.first

/**
 * [ViewModel] backing the key list and key detail screens.
 *
 * Exposes the observable key list plus loading/error state, and coordinates all
 * mutating key operations against the repository and [CryptoOperations]. Every
 * passphrase [CharArray] is zeroed once the corresponding operation completes.
 */
@HiltViewModel
class KeyListViewModel @Inject constructor(
    private val keyRepository: KeyRepository,
    private val cryptoOperations: CryptoOperations,
    private val settingsRepository: SettingsRepository,
) : ViewModel() {
    val keys: StateFlow<List<KeySummary>> = keyRepository.observeKeys()
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    val showFingerprintOnList: StateFlow<Boolean> = settingsRepository.settings
        .map { it.showFingerprintOnList }
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), true)

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    /** Clears the current error message. */
    fun clearError() {
        _error.value = null
    }

    /** Surfaces an externally produced error message to the UI. */
    fun reportError(message: String) {
        _error.value = message
    }

    /**
     * Generates a new key ring for [userId] and imports it into the repository.
     * The [passphrase] is wiped on completion; [onDone] runs on success.
     */
    fun createKey(
        userId: String,
        passphrase: CharArray,
        algorithmType: KeyAlgorithmType,
        rsaBits: Int,
        onDone: () -> Unit,
    ) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                val generated = withContext(Dispatchers.Default) {
                    cryptoOperations.generateKey(userId, passphrase, algorithmType, rsaBits)
                }
                val label = AlgorithmLabels.forKeyType(algorithmType, rsaBits)
                withContext(Dispatchers.IO) {
                    keyRepository.importGeneratedKeyRing(
                        generated.publicArmored,
                        generated.secretArmored,
                        label,
                    )
                }
                onDone()
            } catch (e: Exception) {
                _error.value = e.message ?: "${e.javaClass.simpleName}: Key creation failed"
            } finally {
                passphrase.fill('\u0000')
                _isLoading.value = false
            }
        }
    }

    /** Imports an ASCII-armored key ring; [secret] marks it as a secret import. */
    fun importArmored(armored: String, secret: Boolean, onDone: () -> Unit) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                val bytes = armored.toByteArray(Charsets.UTF_8)
                ImportGuard.checkSize(bytes)
                withContext(Dispatchers.IO) {
                    keyRepository.importKeyRing(bytes, secret)
                }
                onDone()
            } catch (e: Exception) {
                _error.value = e.message ?: "Import failed"
            } finally {
                _isLoading.value = false
            }
        }
    }

    /** Permanently deletes the key ring identified by [keyId]. */
    fun deleteKey(keyId: Long, onDone: (() -> Unit)? = null) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                withContext(Dispatchers.IO) { keyRepository.deleteKey(keyId) }
                // #region agent log
                ltechnologies.onionphone.pgpshield.util.DebugAgentLog.log(
                    location = "KeyListViewModel.kt:deleteKey",
                    message = "key deleted",
                    data = mapOf("keyId" to keyId),
                    hypothesisId = "E",
                )
                // #endregion
                onDone?.invoke()
            } catch (e: Exception) {
                _error.value = e.message ?: "Delete failed"
                // #region agent log
                ltechnologies.onionphone.pgpshield.util.DebugAgentLog.log(
                    location = "KeyListViewModel.kt:deleteKey",
                    message = "delete failed",
                    data = mapOf("keyId" to keyId, "error" to (e.message ?: e.javaClass.simpleName)),
                    hypothesisId = "E",
                )
                // #endregion
            } finally {
                _isLoading.value = false
            }
        }
    }

    /** Marks the key ring identified by [keyId] as revoked. */
    fun revokeKey(keyId: Long) {
        viewModelScope.launch { keyRepository.revokeKey(keyId) }
    }

    /**
     * Adds a subkey of [subkeyType] to the secret key [keyId] and persists the
     * updated public/secret rings. The [passphrase] is wiped on completion.
     */
    fun addSubkey(
        keyId: Long,
        passphrase: CharArray,
        subkeyType: SubkeyType,
        rsaBits: Int,
        onDone: () -> Unit,
    ) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                val secret = withContext(Dispatchers.IO) {
                    keyRepository.getArmoredSecret(keyId)
                        ?: error("Secret key not found")
                }
                val updated = withContext(Dispatchers.Default) {
                    cryptoOperations.addSubkey(secret, passphrase, subkeyType, rsaBits)
                }
                val public = KeyRingExporter.publicArmoredFromSecret(updated)
                withContext(Dispatchers.IO) {
                    keyRepository.replaceSecretKeyRing(keyId, updated, public)
                }
                onDone()
            } catch (e: Exception) {
                _error.value = e.message ?: "Subkey add failed"
                // #region agent log
                ltechnologies.onionphone.pgpshield.util.DebugAgentLog.log(
                    location = "KeyListViewModel.kt:addSubkey",
                    message = "subkey add failed",
                    data = mapOf("keyId" to keyId, "error" to (e.message ?: e.javaClass.simpleName)),
                    hypothesisId = "C",
                )
                // #endregion
            } finally {
                passphrase.fill('\u0000')
                _isLoading.value = false
            }
        }
    }

    /**
     * Re-encrypts the secret key [keyId] from [oldPassphrase] to [newPassphrase].
     * Both passphrase arrays are wiped on completion.
     */
    fun changePassphrase(
        keyId: Long,
        oldPassphrase: CharArray,
        newPassphrase: CharArray,
        onDone: () -> Unit,
    ) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                val secret = withContext(Dispatchers.IO) {
                    keyRepository.getArmoredSecret(keyId)
                        ?: error("Secret key not found")
                }
                val updated = withContext(Dispatchers.Default) {
                    cryptoOperations.changePassphrase(secret, oldPassphrase, newPassphrase)
                }
                withContext(Dispatchers.IO) {
                    keyRepository.changePassphrase(keyId, updated)
                }
                onDone()
            } catch (e: Exception) {
                _error.value = e.message ?: "Passphrase change failed"
            } finally {
                oldPassphrase.fill('\u0000')
                newPassphrase.fill('\u0000')
                _isLoading.value = false
            }
        }
    }

    /** Imports a key ring from raw [bytes]; [secret] marks it as a secret import. */
    fun importFromBytes(bytes: ByteArray, secret: Boolean, onDone: () -> Unit) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                ImportGuard.checkSize(bytes)
                withContext(Dispatchers.IO) {
                    keyRepository.importKeyRing(bytes, secret)
                }
                onDone()
            } catch (e: Exception) {
                _error.value = e.message ?: "Import failed"
            } finally {
                _isLoading.value = false
            }
        }
    }

    /**
     * Generates a revocation certificate for [keyId] with the given [reasonText]
     * and delivers the armored bytes via [onDone]. The [passphrase] is wiped after.
     */
    fun exportRevocationCert(
        keyId: Long,
        passphrase: CharArray,
        reasonText: String,
        onDone: (ByteArray) -> Unit,
    ) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                val cert = withContext(Dispatchers.IO) {
                    keyRepository.generateRevocationCert(keyId, passphrase, reasonText)
                }
                settingsRepository.markKeyExported()
                onDone(cert)
            } catch (e: Exception) {
                _error.value = e.message ?: "Revocation cert failed"
            } finally {
                passphrase.fill('\u0000')
                _isLoading.value = false
            }
        }
    }

    /**
     * Signs (certifies) the [userId] of [targetKeyId] using [certifierKeyId].
     * The [passphrase] is wiped on completion.
     */
    fun certifyKey(
        certifierKeyId: Long,
        targetKeyId: Long,
        passphrase: CharArray,
        userId: String,
        onDone: () -> Unit,
    ) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                withContext(Dispatchers.IO) {
                    keyRepository.certifyKey(certifierKeyId, targetKeyId, passphrase, userId)
                }
                onDone()
            } catch (e: Exception) {
                _error.value = e.message ?: "Certify failed"
            } finally {
                passphrase.fill('\u0000')
                _isLoading.value = false
            }
        }
    }

    /** Refreshes a single key [keyId] from the configured keyserver. */
    fun refreshFromKeyserver(keyId: Long, onDone: () -> Unit) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                val settings = settingsRepository.current()
                if (!settings.keyserverLookupEnabled) {
                    error("Keyserver lookup is disabled in Settings")
                }
                val url = settings.keyserverUrl
                withContext(Dispatchers.IO) {
                    keyRepository.refreshKeyFromKeyserver(keyId, url)
                }
                onDone()
            } catch (e: Exception) {
                _error.value = e.message ?: "Keyserver refresh failed"
            } finally {
                _isLoading.value = false
            }
        }
    }

    /** Refreshes all keys from the keyserver, reporting the success count via [onDone]. */
    fun refreshAllFromKeyserver(onDone: (Int) -> Unit) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                val settings = settingsRepository.current()
                if (!settings.keyserverLookupEnabled) {
                    error("Keyserver lookup is disabled in Settings")
                }
                val url = settings.keyserverUrl
                val keys = keyRepository.observeKeys().first()
                var ok = 0
                withContext(Dispatchers.IO) {
                    for (key in keys) {
                        runCatching {
                            keyRepository.refreshKeyFromKeyserver(key.masterKeyId, url)
                            ok++
                        }
                    }
                }
                onDone(ok)
            } catch (e: Exception) {
                _error.value = e.message ?: "Refresh all failed"
            } finally {
                _isLoading.value = false
            }
        }
    }

    /** Adds a new [userId] to the key [keyId]; the [passphrase] is wiped on completion. */
    fun addUserId(keyId: Long, passphrase: CharArray, userId: String, onDone: () -> Unit) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                withContext(Dispatchers.IO) {
                    keyRepository.addUserId(keyId, passphrase, userId)
                }
                onDone()
            } catch (e: Exception) {
                _error.value = e.message ?: "Add user ID failed"
            } finally {
                passphrase.fill('\u0000')
                _isLoading.value = false
            }
        }
    }

    /** Updates the local owner-trust level for [keyId]. */
    fun setTrustLevel(keyId: Long, trustLevel: Int) {
        viewModelScope.launch {
            try {
                _error.value = null
                withContext(Dispatchers.IO) { keyRepository.setTrustLevel(keyId, trustLevel) }
            } catch (e: Exception) {
                _error.value = e.message ?: "Trust update failed"
            }
        }
    }

    /** Publishes the public key [keyId] to the configured keyserver. */
    fun uploadPublicKey(keyId: Long, onDone: () -> Unit) {
        viewModelScope.launch {
            _isLoading.value = true
            try {
                _error.value = null
                val settings = settingsRepository.current()
                if (!settings.keyserverLookupEnabled) {
                    error("Keyserver lookup is disabled in Settings")
                }
                val url = settings.keyserverUrl
                withContext(Dispatchers.IO) { keyRepository.uploadPublicKey(keyId, url) }
                onDone()
            } catch (e: Exception) {
                _error.value = e.message ?: "Upload failed"
            } finally {
                _isLoading.value = false
            }
        }
    }
}
