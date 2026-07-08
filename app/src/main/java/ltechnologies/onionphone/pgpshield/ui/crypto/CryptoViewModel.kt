package ltechnologies.onionphone.pgpshield.ui.crypto

/**
 * State holder and orchestration for the encrypt/decrypt/sign/verify screen.
 */

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeySummary
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import ltechnologies.onionphone.pgpshield.engine.VerifyResult
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyId
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The kind of payload being operated on in the crypto screen. */
enum class CryptoPayload { TEXT, FILE, FOLDER }

/** UI-facing outcome of a signature verification. */
data class VerifyUiResult(
    val valid: Boolean,
    val signerKeyId: Long?,
    val signerLabel: String?,
    val error: String?,
)

/** Immutable UI state for the crypto screen (inputs, outputs, status, flags). */
data class CryptoUiState(
    val payload: CryptoPayload = CryptoPayload.TEXT,
    val recipientKeyIds: Set<Long> = emptySet(),
    val secretKeyId: Long? = null,
    val plaintext: String = "",
    val ciphertext: String = "",
    val signedInput: String = "",
    val passphrase: String = "",
    val output: String = "",
    val verifyResult: VerifyUiResult? = null,
    val inputFileName: String? = null,
    val inputFileBytes: ByteArray? = null,
    val signatureFileName: String? = null,
    val signatureFileBytes: ByteArray? = null,
    val outputFileName: String? = null,
    val outputFileBytes: ByteArray? = null,
    val folderFiles: List<Pair<String, ByteArray>> = emptyList(),
    val fileStatus: String? = null,
    val error: String? = null,
    val isBusy: Boolean = false,
)

/**
 * [ViewModel] backing the crypto screen.
 *
 * Exposes an observable [CryptoUiState] and the live key list, and drives all
 * encrypt/decrypt/sign/verify operations for text, file and folder payloads.
 * Heavy work runs on background dispatchers; passphrase char arrays are wiped
 * after each operation.
 */
@HiltViewModel
class CryptoViewModel @Inject constructor(
    private val keyRepository: KeyRepository,
    private val cryptoOperations: CryptoOperations,
) : ViewModel() {
    private val _uiState = MutableStateFlow(CryptoUiState())
    val uiState: StateFlow<CryptoUiState> = _uiState.asStateFlow()

    val keys: StateFlow<List<KeySummary>> = keyRepository.observeKeys()
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private var recipientsInitialized = false

    init {
        viewModelScope.launch {
            keys.collect { keyList ->
                val current = _uiState.value
                val prunedRecipients = current.recipientKeyIds.filter { id ->
                    keyList.any { it.masterKeyId == id }
                }.toSet()
                val recipients = when {
                    prunedRecipients.isNotEmpty() -> prunedRecipients
                    !recipientsInitialized && keyList.isNotEmpty() ->
                        setOf(keyList.first().masterKeyId)
                    else -> prunedRecipients
                }
                recipientsInitialized = true
                val secret = current.secretKeyId?.takeIf { id ->
                    keyList.any { it.masterKeyId == id && it.isSecret }
                } ?: keyList.firstOrNull { it.isSecret }?.masterKeyId
                if (recipients != current.recipientKeyIds || secret != current.secretKeyId) {
                    _uiState.value = current.copy(
                        recipientKeyIds = recipients,
                        secretKeyId = secret,
                    )
                }
            }
        }
    }

    /** Switches the active payload type and clears any file/output state. */
    fun setPayload(payload: CryptoPayload) {
        _uiState.value = _uiState.value.copy(
            payload = payload,
            error = null,
            fileStatus = null,
            inputFileName = null,
            inputFileBytes = null,
            signatureFileName = null,
            signatureFileBytes = null,
            outputFileName = null,
            outputFileBytes = null,
            folderFiles = emptyList(),
        )
    }

    /** Reacts to a mode change, downgrading FOLDER payloads for non-encrypt modes. */
    fun onModeChanged(mode: CryptoMode) {
        if (mode != CryptoMode.ENCRYPT && _uiState.value.payload == CryptoPayload.FOLDER) {
            setPayload(CryptoPayload.FILE)
        }
    }

    /** Updates the plaintext input. */
    fun setPlaintext(value: String) {
        _uiState.value = _uiState.value.copy(plaintext = value, error = null)
    }

    /** Updates the ciphertext input. */
    fun setCiphertext(value: String) {
        _uiState.value = _uiState.value.copy(ciphertext = value, error = null)
    }

    /** Updates the signed-text input and resets any prior verification result. */
    fun setSignedInput(value: String) {
        _uiState.value = _uiState.value.copy(signedInput = value, verifyResult = null, error = null)
    }

    /** Updates the passphrase input. */
    fun setPassphrase(value: String) {
        _uiState.value = _uiState.value.copy(passphrase = value, error = null)
    }

    /** Sets the selected input file, enforcing the maximum stream size. */
    fun setInputFile(name: String, bytes: ByteArray) {
        require(bytes.size <= PgpIo.MAX_STREAM_BYTES) {
            "File too large (max ${PgpIo.MAX_STREAM_BYTES / (1024 * 1024)} MB)"
        }
        _uiState.value = _uiState.value.copy(
            inputFileName = name,
            inputFileBytes = bytes,
            outputFileName = null,
            outputFileBytes = null,
            fileStatus = "Loaded $name (${bytes.size} bytes)",
            error = null,
        )
    }

    /** Sets the files for folder encryption, enforcing the total size limit. */
    fun setFolderFiles(files: List<Pair<String, ByteArray>>) {
        val total = files.sumOf { it.second.size }
        require(total <= PgpIo.MAX_STREAM_BYTES) {
            "Folder too large (max ${PgpIo.MAX_STREAM_BYTES / (1024 * 1024)} MB total)"
        }
        _uiState.value = _uiState.value.copy(
            folderFiles = files,
            fileStatus = "${files.size} files selected ($total bytes)",
            error = null,
        )
    }

    /** Sets the detached signature file used for verification. */
    fun setSignatureFile(name: String, bytes: ByteArray) {
        require(bytes.size <= PgpIo.MAX_STREAM_BYTES) {
            "Signature file too large"
        }
        _uiState.value = _uiState.value.copy(
            signatureFileName = name,
            signatureFileBytes = bytes,
            fileStatus = "Signature: $name",
            error = null,
        )
    }

    /** Clears any produced output file. */
    fun clearOutputFile() {
        _uiState.value = _uiState.value.copy(outputFileName = null, outputFileBytes = null)
    }

    /** Replaces the set of recipient key ids. */
    fun setRecipientKeyIds(ids: Set<Long>) {
        _uiState.value = _uiState.value.copy(recipientKeyIds = ids, error = null)
    }

    /** Adds or removes [keyId] from the recipient set. */
    fun toggleRecipient(keyId: Long) {
        val current = _uiState.value.recipientKeyIds
        val next = if (keyId in current) current - keyId else current + keyId
        _uiState.value = _uiState.value.copy(recipientKeyIds = next, error = null)
    }

    /** Selects the secret key used for decrypt/sign operations. */
    fun selectSecretKey(keyId: Long) {
        _uiState.value = _uiState.value.copy(secretKeyId = keyId, error = null)
    }

    /** Encrypts the current payload according to the active [CryptoPayload]. */
    fun encrypt() {
        when (_uiState.value.payload) {
            CryptoPayload.FILE -> encryptFile()
            CryptoPayload.FOLDER -> encryptFolder()
            CryptoPayload.TEXT -> encryptText()
        }
    }

    private fun encryptText() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBusy = true, error = null)
            try {
                val ids = _uiState.value.recipientKeyIds
                require(ids.isNotEmpty()) { "Select at least one recipient key" }
                val publicKeys = withContext(Dispatchers.IO) {
                    ids.mapNotNull { keyRepository.getArmoredPublic(it) }
                }
                require(publicKeys.size == ids.size) { "Public key missing for a recipient" }
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.encrypt(
                        _uiState.value.plaintext.toByteArray(Charsets.UTF_8),
                        publicKeys,
                    )
                }
                _uiState.value = _uiState.value.copy(
                    output = String(result.ciphertext, Charsets.UTF_8),
                    error = null,
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message)
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    /** Encrypts the selected input file to the chosen recipients. */
    fun encryptFile() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBusy = true, error = null)
            try {
                val input = _uiState.value.inputFileBytes ?: error("Pick a file to encrypt")
                val name = _uiState.value.inputFileName ?: "file.bin"
                val ids = _uiState.value.recipientKeyIds
                require(ids.isNotEmpty()) { "Select at least one recipient key" }
                val publicKeys = withContext(Dispatchers.IO) {
                    ids.mapNotNull { keyRepository.getArmoredPublic(it) }
                }
                require(publicKeys.size == ids.size) { "Public key missing for a recipient" }
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.encrypt(input, publicKeys, asciiArmor = false, fileName = name)
                }
                val outName = CryptoFileHelper.guessEncryptedName(name)
                _uiState.value = _uiState.value.copy(
                    outputFileBytes = result.ciphertext,
                    outputFileName = outName,
                    fileStatus = "Encrypted → $outName (${result.ciphertext.size} bytes)",
                    error = null,
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message)
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    /** Packs the selected files into a tar archive and encrypts it. */
    fun encryptFolder() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBusy = true, error = null)
            try {
                val files = _uiState.value.folderFiles
                require(files.isNotEmpty()) { "Pick at least one file for the archive" }
                val ids = _uiState.value.recipientKeyIds
                require(ids.isNotEmpty()) { "Select at least one recipient key" }
                val publicKeys = withContext(Dispatchers.IO) {
                    ids.mapNotNull { keyRepository.getArmoredPublic(it) }
                }
                require(publicKeys.size == ids.size) { "Public key missing for a recipient" }
                val named = files.map { (name, data) ->
                    ltechnologies.onionphone.pgpshield.engine.NamedFile(name, data)
                }
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.encryptTar(named, publicKeys, asciiArmor = false)
                }
                val outName = "archive.gpg"
                _uiState.value = _uiState.value.copy(
                    outputFileBytes = result.ciphertext,
                    outputFileName = outName,
                    fileStatus = "Encrypted folder → $outName (${result.ciphertext.size} bytes)",
                    error = null,
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message)
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    /** Decrypts the current text (or delegates to [decryptFile] for files). */
    fun decrypt() {
        if (_uiState.value.payload == CryptoPayload.FILE) {
            decryptFile()
            return
        }
        viewModelScope.launch {
            var passphrase: CharArray? = null
            _uiState.value = _uiState.value.copy(isBusy = true, error = null)
            try {
                val keyId = _uiState.value.secretKeyId ?: error("Select your secret key")
                val key = keys.value.find { it.masterKeyId == keyId } ?: error("Key not found")
                if (!key.isSecret) error("Select a secret key to decrypt")
                val armored = withContext(Dispatchers.IO) {
                    keyRepository.getArmoredSecret(keyId) ?: error("Secret missing")
                }
                passphrase = requirePassphrase()
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.decrypt(
                        _uiState.value.ciphertext.toByteArray(Charsets.UTF_8),
                        armored,
                        passphrase,
                    )
                }
                _uiState.value = _uiState.value.copy(
                    plaintext = String(result.plaintext, Charsets.UTF_8),
                    error = null,
                    passphrase = "",
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message)
            } finally {
                passphrase?.fill('\u0000')
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    /** Decrypts the selected encrypted file using the chosen secret key. */
    fun decryptFile() {
        viewModelScope.launch {
            var passphrase: CharArray? = null
            _uiState.value = _uiState.value.copy(isBusy = true, error = null, outputFileBytes = null, outputFileName = null)
            try {
                val input = _uiState.value.inputFileBytes ?: error("Pick an encrypted file (.gpg)")
                val name = _uiState.value.inputFileName ?: "file.gpg"
                val keyId = _uiState.value.secretKeyId ?: error("Select your secret key")
                val key = keys.value.find { it.masterKeyId == keyId } ?: error("Key not found")
                if (!key.isSecret) error("Select a secret key to decrypt")
                val armored = withContext(Dispatchers.IO) {
                    keyRepository.getArmoredSecret(keyId) ?: error("Secret missing")
                }
                passphrase = requirePassphrase()
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.decrypt(input, armored, passphrase)
                }
                val outName = result.fileName?.takeIf { it.isNotBlank() && it != "_CONSOLE" }
                    ?: CryptoFileHelper.guessDecryptedName(name)
                _uiState.value = _uiState.value.copy(
                    outputFileBytes = result.plaintext,
                    outputFileName = outName,
                    fileStatus = "Decrypted → $outName (${result.plaintext.size} bytes)",
                    error = null,
                    passphrase = "",
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message)
            } finally {
                passphrase?.fill('\u0000')
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    /** Clear-signs the current text (or delegates to [signFile] for files). */
    fun sign() {
        if (_uiState.value.payload == CryptoPayload.FILE) {
            signFile()
            return
        }
        viewModelScope.launch {
            var passphrase: CharArray? = null
            _uiState.value = _uiState.value.copy(isBusy = true, error = null)
            try {
                val keyId = _uiState.value.secretKeyId ?: error("Select your secret key")
                val key = keys.value.find { it.masterKeyId == keyId } ?: error("Key not found")
                if (!key.isSecret) error("Select a secret key to sign")
                val armored = withContext(Dispatchers.IO) {
                    keyRepository.getArmoredSecret(keyId) ?: error("Secret missing")
                }
                passphrase = requirePassphrase()
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.sign(
                        _uiState.value.plaintext.toByteArray(Charsets.UTF_8),
                        armored,
                        passphrase,
                    )
                }
                _uiState.value = _uiState.value.copy(
                    output = String(result.output, Charsets.UTF_8),
                    error = null,
                    passphrase = "",
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message)
            } finally {
                passphrase?.fill('\u0000')
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    /** Produces a detached binary signature for the selected file. */
    fun signFile() {
        viewModelScope.launch {
            var passphrase: CharArray? = null
            _uiState.value = _uiState.value.copy(isBusy = true, error = null, outputFileBytes = null, outputFileName = null)
            try {
                val input = _uiState.value.inputFileBytes ?: error("Pick a file to sign")
                val name = _uiState.value.inputFileName ?: "file.bin"
                val keyId = _uiState.value.secretKeyId ?: error("Select your secret key")
                val key = keys.value.find { it.masterKeyId == keyId } ?: error("Key not found")
                if (!key.isSecret) error("Select a secret key to sign")
                val armored = withContext(Dispatchers.IO) {
                    keyRepository.getArmoredSecret(keyId) ?: error("Secret missing")
                }
                passphrase = requirePassphrase()
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.sign(input, armored, passphrase, detachedBinary = true)
                }
                val outName = CryptoFileHelper.guessSignatureName(name)
                _uiState.value = _uiState.value.copy(
                    outputFileBytes = result.output,
                    outputFileName = outName,
                    fileStatus = "Signed → $outName (detached)",
                    error = null,
                    passphrase = "",
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message)
            } finally {
                passphrase?.fill('\u0000')
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    /** Verifies the signed text (or delegates to [verifyFile] for files). */
    fun verify() {
        if (_uiState.value.payload == CryptoPayload.FILE) {
            verifyFile()
            return
        }
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBusy = true, error = null, verifyResult = null)
            try {
                val signed = _uiState.value.signedInput.toByteArray(Charsets.UTF_8)
                val result = verifyIncrementally(signed)
                applyVerifyResult(result)
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message)
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    /** Verifies a detached signature against the selected signed file. */
    fun verifyFile() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBusy = true, error = null, verifyResult = null)
            try {
                val data = _uiState.value.inputFileBytes ?: error("Pick the signed file")
                val sig = _uiState.value.signatureFileBytes ?: error("Pick the .sig signature file")
                val result = verifyIncrementally(sig, message = data, binaryDocument = true)
                applyVerifyResult(result)
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message)
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    private suspend fun verifyIncrementally(
        signed: ByteArray,
        message: ByteArray? = null,
        binaryDocument: Boolean = false,
    ): VerifyResult {
        var last = VerifyResult(valid = false, error = "No matching public key")
        for (key in keys.value) {
            val armored = withContext(Dispatchers.IO) {
                keyRepository.getArmoredPublic(key.masterKeyId)
            } ?: continue
            val result = withContext(Dispatchers.Default) {
                cryptoOperations.verify(signed, listOf(armored), message = message, binaryDocument = binaryDocument)
            }
            if (result.valid) return result
            last = result
        }
        return last
    }

    private fun applyVerifyResult(result: ltechnologies.onionphone.pgpshield.engine.VerifyResult) {
        val signer = result.signerKeyId?.let { id ->
            keys.value.find { it.masterKeyId == id }
        }
        val label = signer?.primaryUserId
            ?: result.signerKeyId?.let { formatKeyId(it) }
        _uiState.value = _uiState.value.copy(
            verifyResult = VerifyUiResult(
                valid = result.valid,
                signerKeyId = result.signerKeyId,
                signerLabel = label,
                error = result.error,
            ),
            fileStatus = if (result.valid) "Valid detached signature" else result.error,
            error = null,
        )
    }

    private fun requirePassphrase(): CharArray {
        val inline = _uiState.value.passphrase
        require(inline.isNotBlank()) { "Enter your key passphrase" }
        return inline.toCharArray()
    }
}
