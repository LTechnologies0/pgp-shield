package ltechnologies.onionphone.pgpshield.ui.crypto

/**
 * State holder and orchestration for the encrypt/decrypt/sign/verify screen.
 */

import android.content.Context
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import dagger.hilt.android.qualifiers.ApplicationContext
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.AutocryptManager
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeySummary
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.data.SmimeCertificateStore
import ltechnologies.onionphone.pgpshield.engine.CryptoProgress
import ltechnologies.onionphone.pgpshield.engine.CryptoStage
import ltechnologies.onionphone.pgpshield.engine.InteropProfile
import ltechnologies.onionphone.pgpshield.engine.MessageCompression
import ltechnologies.onionphone.pgpshield.engine.MessageIntegrity
import ltechnologies.onionphone.pgpshield.engine.PgpIo
import ltechnologies.onionphone.pgpshield.engine.SmimeIdentity
import ltechnologies.onionphone.pgpshield.engine.VerifyResult
import ltechnologies.onionphone.pgpshield.security.HardwarePassphraseGate
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyId
import ltechnologies.onionphone.pgpshield.util.SensitiveWiper
import java.util.Base64
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** The kind of payload being operated on in the crypto screen. */
enum class CryptoPayload { TEXT, FILE, FOLDER }

/** OpenPGP vs CMS/S-MIME wire format for crypto ops. */
enum class CryptoFormat { OPENPGP, SMIME }

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
    /** Increments when passphrase buffers are wiped so Compose TextFields can reset. */
    val sensitiveInputEpoch: Long = 0L,
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
    /** Determinate 0f..1f while a profiled crypto op runs; null when idle. */
    val progress: Float? = null,
    val progressStage: CryptoStage? = null,
    val progressElapsedMs: Long = 0L,
    /** Local-only resource summary after the last completed op (no payloads). */
    val resourceSummary: ltechnologies.onionphone.pgpshield.engine.CryptoResourceSummary? = null,
    val messageIntegrity: MessageIntegrity = MessageIntegrity.SEIPD_V2_AEAD,
    val messageCompression: MessageCompression = MessageCompression.NONE,
    val format: CryptoFormat = CryptoFormat.OPENPGP,
    val smimeRecipientAliases: Set<String> = emptySet(),
    val smimeIdentityAlias: String? = null,
    val smimeIdentities: List<SmimeIdentity> = emptyList(),
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
    @ApplicationContext private val context: Context,
    private val keyRepository: KeyRepository,
    private val cryptoOperations: CryptoOperations,
    private val smimeStore: SmimeCertificateStore,
    private val autocryptManager: AutocryptManager,
    private val hardwarePassphraseGate: HardwarePassphraseGate,
    private val settingsRepository: SettingsRepository,
) : ViewModel() {
    private val _uiState = MutableStateFlow(CryptoUiState())
    val uiState: StateFlow<CryptoUiState> = _uiState.asStateFlow()

    val keys: StateFlow<List<KeySummary>> = keyRepository.observeKeys()
        .distinctUntilChanged()
        .stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), emptyList())

    private var recipientsInitialized = false
    private var lastInteropProfile: String? = null

    /** Wipeable passphrase buffer — source of truth for crypto ops (not the UI String copy). */
    @Volatile
    private var passphraseChars: CharArray = CharArray(0)

    @Volatile
    private var pkcs12PasswordChars: CharArray = CharArray(0)

    /** Host activity for BiometricPrompt CryptoObject (hardware-managed passphrases). */
    @Volatile
    private var hostActivity: java.lang.ref.WeakReference<FragmentActivity>? = null

    fun bindHost(activity: FragmentActivity) {
        hostActivity = java.lang.ref.WeakReference(activity)
    }

    init {
        refreshSmimeIdentities()
        viewModelScope.launch {
            settingsRepository.settings.collect { settings ->
                if (settings.interopProfile == lastInteropProfile) return@collect
                lastInteropProfile = settings.interopProfile
                val integrity = InteropProfile.fromName(settings.interopProfile).defaultIntegrity()
                _uiState.update { it.copy(messageIntegrity = integrity) }
            }
        }
        viewModelScope.launch {
            keys.collect { keyList ->
                val current = _uiState.value
                val prunedRecipients = current.recipientKeyIds.filter { id ->
                    keyList.any {
                        it.masterKeyId == id && it.isEncryptPickerCandidate()
                    }
                }.toSet()
                val recipients = when {
                    prunedRecipients.isNotEmpty() -> prunedRecipients
                    // OpenKeychain-style: do not auto-pick the user's own key as encrypt recipient.
                    !recipientsInitialized -> emptySet()
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
        viewModelScope.launch {
            CryptoProgress.snapshots.collect { snap ->
                if (snap == null) return@collect
                _uiState.update { state ->
                    if (!state.isBusy && snap.running) {
                        // Ignore foreign sessions (e.g. keygen on another screen) unless busy.
                        return@update state
                    }
                    if (snap.running) {
                        state.copy(
                            progress = snap.progress,
                            progressStage = snap.stage,
                            progressElapsedMs = snap.elapsedMs,
                        )
                    } else {
                        state.copy(
                            progress = if (state.isBusy) 1f else null,
                            progressStage = if (state.isBusy) CryptoStage.DONE else null,
                            progressElapsedMs = snap.elapsedMs,
                            resourceSummary = snap.summary ?: state.resourceSummary,
                        )
                    }
                }
            }
        }
    }

    private fun markBusy(clearVerify: Boolean = false) {
        _uiState.value = _uiState.value.copy(
            isBusy = true,
            error = null,
            progress = 0.02f,
            progressStage = CryptoStage.PREPARE,
            progressElapsedMs = 0L,
            resourceSummary = null,
            verifyResult = if (clearVerify) null else _uiState.value.verifyResult,
        )
    }

    private fun clearBusy() {
        _uiState.value = _uiState.value.copy(
            isBusy = false,
            progress = null,
            progressStage = null,
        )
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

    /** Updates the passphrase CharArray buffer (Compose keeps TextField state locally). */
    fun setPassphrase(value: String) {
        SensitiveWiper.wipe(passphraseChars)
        passphraseChars = value.toCharArray()
        if (_uiState.value.error != null) {
            _uiState.value = _uiState.value.copy(error = null)
        }
    }

    /** Clears passphrase / PKCS#12 buffers and bumps [CryptoUiState.sensitiveInputEpoch]. */
    fun clearSensitiveInputs() {
        SensitiveWiper.wipe(passphraseChars, pkcs12PasswordChars)
        passphraseChars = CharArray(0)
        pkcs12PasswordChars = CharArray(0)
        _uiState.update {
            it.copy(sensitiveInputEpoch = it.sensitiveInputEpoch + 1)
        }
    }

    override fun onCleared() {
        clearSensitiveInputs()
        super.onCleared()
    }

    /** Sets the selected input file, enforcing the maximum stream size. */
    fun setInputFile(name: String, bytes: ByteArray) {
        require(bytes.size <= PgpIo.MAX_STREAM_BYTES) {
            context.getString(R.string.crypto_file_too_large_fmt, PgpIo.MAX_STREAM_BYTES / (1024 * 1024))
        }
        _uiState.value = _uiState.value.copy(
            inputFileName = name,
            inputFileBytes = bytes,
            outputFileName = null,
            outputFileBytes = null,
            fileStatus = context.getString(R.string.crypto_status_loaded_fmt, name, bytes.size),
            error = null,
            isBusy = false,
            progress = null,
            progressStage = null,
        )
    }

    /** Reads and sets an input file while showing busy state. */
    fun loadInputFile(loader: suspend () -> Pair<String, ByteArray>?) {
        viewModelScope.launch {
            markBusy()
            try {
                val loaded = loader()
                if (loaded == null) {
                    clearBusy()
                    return@launch
                }
                setInputFile(loaded.first, loaded.second)
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
                clearBusy()
            }
        }
    }

    /** Sets the files for folder encryption, enforcing the total size limit. */
    fun setFolderFiles(files: List<Pair<String, ByteArray>>) {
        val total = files.sumOf { it.second.size }
        require(total <= PgpIo.MAX_STREAM_BYTES) {
            context.getString(R.string.crypto_folder_too_large_fmt, PgpIo.MAX_STREAM_BYTES / (1024 * 1024))
        }
        _uiState.value = _uiState.value.copy(
            folderFiles = files,
            fileStatus = context.getString(R.string.crypto_status_files_selected_fmt, files.size, total),
            error = null,
            isBusy = false,
            progress = null,
            progressStage = null,
        )
    }

    /** Reads multiple files for folder encrypt while showing busy state. */
    fun loadFolderFiles(loader: suspend () -> List<Pair<String, ByteArray>>) {
        viewModelScope.launch {
            markBusy()
            try {
                setFolderFiles(loader())
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
                clearBusy()
            }
        }
    }

    /** Sets the detached signature file used for verification. */
    fun setSignatureFile(name: String, bytes: ByteArray) {
        require(bytes.size <= PgpIo.MAX_STREAM_BYTES) {
            context.getString(R.string.crypto_signature_too_large)
        }
        _uiState.value = _uiState.value.copy(
            signatureFileName = name,
            signatureFileBytes = bytes,
            fileStatus = context.getString(R.string.crypto_status_signature_fmt, name),
            error = null,
            isBusy = false,
            progress = null,
            progressStage = null,
        )
    }

    /** Reads a detached signature file while showing busy state. */
    fun loadSignatureFile(loader: suspend () -> Pair<String, ByteArray>?) {
        viewModelScope.launch {
            markBusy()
            try {
                val loaded = loader()
                if (loaded == null) {
                    clearBusy()
                    return@launch
                }
                setSignatureFile(loaded.first, loaded.second)
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
                clearBusy()
            }
        }
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

    fun setMessageIntegrity(integrity: MessageIntegrity) {
        _uiState.value = _uiState.value.copy(messageIntegrity = integrity)
    }

    fun setMessageCompression(compression: MessageCompression) {
        _uiState.value = _uiState.value.copy(messageCompression = compression)
    }

    fun setFormat(format: CryptoFormat) {
        _uiState.value = _uiState.value.copy(format = format, error = null)
        if (format == CryptoFormat.SMIME) refreshSmimeIdentities()
    }

    fun setSmimeRecipientAliases(aliases: Set<String>) {
        _uiState.value = _uiState.value.copy(smimeRecipientAliases = aliases, error = null)
    }

    fun selectSmimeIdentity(alias: String) {
        _uiState.value = _uiState.value.copy(smimeIdentityAlias = alias, error = null)
    }

    fun setSmimePkcs12Password(value: String) {
        SensitiveWiper.wipe(pkcs12PasswordChars)
        pkcs12PasswordChars = value.toCharArray()
    }

    fun refreshSmimeIdentities() {
        viewModelScope.launch(Dispatchers.IO) {
            val list = smimeStore.listIdentities()
            _uiState.update { state ->
                state.copy(
                    smimeIdentities = list,
                    smimeIdentityAlias = state.smimeIdentityAlias?.takeIf { a -> list.any { it.alias == a } }
                        ?: list.firstOrNull { it.privateKey != null }?.alias
                        ?: list.firstOrNull()?.alias,
                    smimeRecipientAliases = state.smimeRecipientAliases.filter { a -> list.any { it.alias == a } }
                        .ifEmpty { list.take(1).map { it.alias }.toSet() }
                        .toSet(),
                )
            }
        }
    }

    /** Imports a PKCS#12 blob into the S/MIME certificate store. */
    fun importSmimePkcs12(bytes: ByteArray) {
        viewModelScope.launch {
            markBusy()
            val password = pkcs12PasswordChars.copyOf()
            try {
                withContext(Dispatchers.IO) {
                    smimeStore.importPkcs12(bytes, password)
                }
                refreshSmimeIdentities()
                SensitiveWiper.wipe(pkcs12PasswordChars)
                pkcs12PasswordChars = CharArray(0)
                _uiState.value = _uiState.value.copy(
                    fileStatus = context.getString(R.string.crypto_status_smime_imported),
                    error = null,
                    sensitiveInputEpoch = _uiState.value.sensitiveInputEpoch + 1,
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                SensitiveWiper.wipe(password)
                clearBusy()
            }
        }
    }

    /**
     * Adds Autocrypt-discovered peer key ids for [email] fragments found in recipient selection hints.
     * Call with raw email addresses to expand [recipientKeyIds].
     */
    fun addAutocryptRecipients(emails: Iterable<String>) {
        viewModelScope.launch {
            val extra = emails.mapNotNull { email ->
                val id = autocryptManager.lookup(email.trim()) ?: return@mapNotNull null
                val allowed = withContext(Dispatchers.IO) {
                    keyRepository.isEncryptRecipientAllowed(id)
                }
                id.takeIf { allowed }
            }.toSet()
            if (extra.isEmpty()) return@launch
            _uiState.update { it.copy(recipientKeyIds = it.recipientKeyIds + extra) }
        }
    }

    /** Encrypts the current payload according to the active [CryptoPayload]. */
    fun encrypt() {
        if (_uiState.value.format == CryptoFormat.SMIME) {
            encryptSmime()
            return
        }
        when (_uiState.value.payload) {
            CryptoPayload.FILE -> encryptFile()
            CryptoPayload.FOLDER -> encryptFolder()
            CryptoPayload.TEXT -> encryptText()
        }
    }

    private fun encryptSmime() {
        viewModelScope.launch {
            markBusy()
            try {
                require(_uiState.value.payload != CryptoPayload.FOLDER) {
                    context.getString(R.string.crypto_smime_folder_encrypt_unsupported)
                }
                val aliases = _uiState.value.smimeRecipientAliases
                require(aliases.isNotEmpty()) { context.getString(R.string.crypto_smime_select_recipient) }
                val certs = _uiState.value.smimeIdentities
                    .filter { it.alias in aliases }
                    .map { it.certificate }
                require(certs.size == aliases.size) { context.getString(R.string.crypto_smime_cert_missing) }
                val plaintext = when (_uiState.value.payload) {
                    CryptoPayload.TEXT -> _uiState.value.plaintext.toByteArray(Charsets.UTF_8)
                    CryptoPayload.FILE -> _uiState.value.inputFileBytes ?: error(context.getString(R.string.crypto_pick_file_encrypt))
                    CryptoPayload.FOLDER -> error("unreachable")
                }
                val cms = withContext(Dispatchers.Default) {
                    cryptoOperations.smimeEncrypt(plaintext, certs)
                }
                if (_uiState.value.payload == CryptoPayload.TEXT) {
                    _uiState.value = _uiState.value.copy(
                        output = Base64.getMimeEncoder().encodeToString(cms),
                        error = null,
                    )
                } else {
                    val name = (_uiState.value.inputFileName ?: "file.bin") + ".p7m"
                    _uiState.value = _uiState.value.copy(
                        outputFileBytes = cms,
                        outputFileName = name,
                        fileStatus = context.getString(R.string.crypto_status_smime_encrypted_fmt, name, cms.size),
                        error = null,
                    )
                }
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                clearBusy()
            }
        }
    }

    private fun encryptText() {
        viewModelScope.launch {
            markBusy()
            try {
                val ids = _uiState.value.recipientKeyIds
                require(ids.isNotEmpty()) { context.getString(R.string.crypto_select_recipient_key) }
                requireEncryptableRecipients(ids)
                val publicKeys = withContext(Dispatchers.IO) {
                    loadPublicKeysParallel(ids)
                }
                require(publicKeys.size == ids.size) { context.getString(R.string.crypto_public_key_missing) }
                val requested = _uiState.value.messageIntegrity
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.encryptSuspending(
                        _uiState.value.plaintext.toByteArray(Charsets.UTF_8),
                        publicKeys,
                        integrity = requested,
                        compression = _uiState.value.messageCompression,
                        allowMdcDegrade = requested == MessageIntegrity.SEIPD_V2_AEAD,
                    )
                }
                _uiState.value = _uiState.value.copy(
                    output = String(result.ciphertext, Charsets.UTF_8),
                    fileStatus = mdcDegradeStatus(requested, result.integrity),
                    error = null,
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                clearBusy()
            }
        }
    }

    /** Encrypts the selected input file to the chosen recipients. */
    fun encryptFile() {
        viewModelScope.launch {
            markBusy()
            try {
                val input = _uiState.value.inputFileBytes ?: error(context.getString(R.string.crypto_pick_file_encrypt))
                val name = _uiState.value.inputFileName ?: "file.bin"
                val ids = _uiState.value.recipientKeyIds
                require(ids.isNotEmpty()) { context.getString(R.string.crypto_select_recipient_key) }
                requireEncryptableRecipients(ids)
                val publicKeys = withContext(Dispatchers.IO) {
                    loadPublicKeysParallel(ids)
                }
                require(publicKeys.size == ids.size) { context.getString(R.string.crypto_public_key_missing) }
                val requested = _uiState.value.messageIntegrity
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.encryptSuspending(
                        input,
                        publicKeys,
                        asciiArmor = false,
                        fileName = name,
                        integrity = requested,
                        compression = _uiState.value.messageCompression,
                        allowMdcDegrade = requested == MessageIntegrity.SEIPD_V2_AEAD,
                    )
                }
                val outName = CryptoFileHelper.guessEncryptedName(name)
                val base = context.getString(R.string.crypto_status_encrypted_fmt, outName, result.ciphertext.size)
                val note = mdcDegradeStatus(requested, result.integrity)
                _uiState.value = _uiState.value.copy(
                    outputFileBytes = result.ciphertext,
                    outputFileName = outName,
                    fileStatus = if (note != null) "$base · $note" else base,
                    error = null,
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                clearBusy()
            }
        }
    }

    /** Packs the selected files into a tar archive and encrypts it. */
    fun encryptFolder() {
        viewModelScope.launch {
            markBusy()
            try {
                val files = _uiState.value.folderFiles
                require(files.isNotEmpty()) { context.getString(R.string.crypto_pick_archive_files) }
                val ids = _uiState.value.recipientKeyIds
                require(ids.isNotEmpty()) { context.getString(R.string.crypto_select_recipient_key) }
                requireEncryptableRecipients(ids)
                val publicKeys = withContext(Dispatchers.IO) {
                    loadPublicKeysParallel(ids)
                }
                require(publicKeys.size == ids.size) { context.getString(R.string.crypto_public_key_missing) }
                val named = files.map { (name, data) ->
                    ltechnologies.onionphone.pgpshield.engine.NamedFile(name, data)
                }
                val requested = _uiState.value.messageIntegrity
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.encryptTar(
                        named,
                        publicKeys,
                        asciiArmor = false,
                        allowMdcDegrade = requested == MessageIntegrity.SEIPD_V2_AEAD,
                    )
                }
                val outName = "archive.gpg"
                val base = context.getString(
                    R.string.crypto_status_encrypted_folder_fmt,
                    outName,
                    result.ciphertext.size,
                )
                val note = mdcDegradeStatus(requested, result.integrity)
                _uiState.value = _uiState.value.copy(
                    outputFileBytes = result.ciphertext,
                    outputFileName = outName,
                    fileStatus = if (note != null) "$base · $note" else base,
                    error = null,
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                clearBusy()
            }
        }
    }

    /** Decrypts the current text (or delegates to [decryptFile] for files). */
    fun decrypt() {
        if (_uiState.value.format == CryptoFormat.SMIME) {
            decryptSmime()
            return
        }
        if (_uiState.value.payload == CryptoPayload.FILE) {
            decryptFile()
            return
        }
        viewModelScope.launch {
            var passphrase: CharArray? = null
            markBusy()
            try {
                val keyId = _uiState.value.secretKeyId ?: error(context.getString(R.string.crypto_select_secret_key))
                val key = keys.value.find { it.masterKeyId == keyId } ?: error(context.getString(R.string.crypto_key_not_found))
                if (!key.isSecret) error(context.getString(R.string.crypto_select_secret_decrypt))
                val armored = withContext(Dispatchers.IO) {
                    keyRepository.getArmoredSecret(keyId) ?: error(context.getString(R.string.crypto_secret_missing))
                }
                passphrase = passphraseForKey(keyId)
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.decrypt(
                        _uiState.value.ciphertext.toByteArray(Charsets.UTF_8),
                        armored,
                        passphrase,
                    )
                }
                maybeUpgradeSecretProtection(keyId, armored, passphrase)
                // Autocrypt: ingest headers if the plaintext looks like an email.
                val text = String(result.plaintext, Charsets.UTF_8)
                withContext(Dispatchers.IO) {
                    autocryptManager.storeFromHeaderLines(text.lineSequence().take(80).asIterable())
                }
                _uiState.value = _uiState.value.copy(
                    plaintext = text,
                    error = null,
                )
                wipePassphraseUi()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                SensitiveWiper.wipe(passphrase)
                clearBusy()
            }
        }
    }

    /** Rewraps legacy S2K secrets to Argon2+AEAD after a successful unlock. */
    private suspend fun maybeUpgradeSecretProtection(
        keyId: Long,
        secretArmored: ByteArray,
        passphrase: CharArray,
    ) {
        val upgraded = withContext(Dispatchers.Default) {
            cryptoOperations.upgradeSecretProtectionIfNeeded(secretArmored, passphrase)
        } ?: return
        val publicArmored = withContext(Dispatchers.IO) {
            keyRepository.getArmoredPublic(keyId)
        } ?: return
        withContext(Dispatchers.IO) {
            keyRepository.replaceSecretKeyRing(keyId, upgraded, publicArmored)
        }
    }

    private fun decryptSmime() {
        viewModelScope.launch {
            markBusy()
            try {
                val alias = _uiState.value.smimeIdentityAlias ?: error(context.getString(R.string.crypto_smime_select_identity))
                val identity = _uiState.value.smimeIdentities.find { it.alias == alias }
                    ?: error(context.getString(R.string.crypto_smime_identity_not_found))
                val privateKey = identity.privateKey ?: error(context.getString(R.string.crypto_smime_no_private_key))
                val ciphertext = when (_uiState.value.payload) {
                    CryptoPayload.TEXT -> {
                        val raw = _uiState.value.ciphertext.trim()
                        runCatching { Base64.getMimeDecoder().decode(raw) }.getOrElse {
                            raw.toByteArray(Charsets.UTF_8)
                        }
                    }
                    CryptoPayload.FILE -> _uiState.value.inputFileBytes ?: error(context.getString(R.string.crypto_pick_p7m))
                    CryptoPayload.FOLDER -> error(context.getString(R.string.crypto_smime_folder_decrypt_unsupported))
                }
                val plain = withContext(Dispatchers.Default) {
                    cryptoOperations.smimeDecrypt(ciphertext, privateKey)
                }
                if (_uiState.value.payload == CryptoPayload.TEXT) {
                    _uiState.value = _uiState.value.copy(
                        plaintext = String(plain, Charsets.UTF_8),
                        error = null,
                    )
                } else {
                    val outName = CryptoFileHelper.guessDecryptedName(_uiState.value.inputFileName ?: "file.p7m")
                    _uiState.value = _uiState.value.copy(
                        outputFileBytes = plain,
                        outputFileName = outName,
                        fileStatus = context.getString(R.string.crypto_status_smime_decrypted_fmt, outName),
                        error = null,
                    )
                }
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                clearBusy()
            }
        }
    }

    /** Decrypts the selected encrypted file using the chosen secret key. */
    fun decryptFile() {
        viewModelScope.launch {
            var passphrase: CharArray? = null
            _uiState.value = _uiState.value.copy(outputFileBytes = null, outputFileName = null)
            markBusy()
            try {
                val input = _uiState.value.inputFileBytes ?: error(context.getString(R.string.crypto_pick_encrypted_gpg))
                val name = _uiState.value.inputFileName ?: "file.gpg"
                val keyId = _uiState.value.secretKeyId ?: error(context.getString(R.string.crypto_select_secret_key))
                val key = keys.value.find { it.masterKeyId == keyId } ?: error(context.getString(R.string.crypto_key_not_found))
                if (!key.isSecret) error(context.getString(R.string.crypto_select_secret_decrypt))
                val armored = withContext(Dispatchers.IO) {
                    keyRepository.getArmoredSecret(keyId) ?: error(context.getString(R.string.crypto_secret_missing))
                }
                passphrase = passphraseForKey(keyId)
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.decrypt(input, armored, passphrase)
                }
                maybeUpgradeSecretProtection(keyId, armored, passphrase)
                val outName = result.fileName?.takeIf { it.isNotBlank() && it != "_CONSOLE" }
                    ?: CryptoFileHelper.guessDecryptedName(name)
                _uiState.value = _uiState.value.copy(
                    outputFileBytes = result.plaintext,
                    outputFileName = outName,
                    fileStatus = context.getString(R.string.crypto_status_decrypted_fmt, outName, result.plaintext.size),
                    error = null,
                )
                wipePassphraseUi()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                SensitiveWiper.wipe(passphrase)
                clearBusy()
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
            markBusy()
            try {
                val keyId = _uiState.value.secretKeyId ?: error(context.getString(R.string.crypto_select_secret_key))
                val key = keys.value.find { it.masterKeyId == keyId } ?: error(context.getString(R.string.crypto_key_not_found))
                if (!key.isSecret) error(context.getString(R.string.crypto_select_secret_sign))
                val armored = withContext(Dispatchers.IO) {
                    keyRepository.getArmoredSecret(keyId) ?: error(context.getString(R.string.crypto_secret_missing))
                }
                passphrase = passphraseForKey(keyId)
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.sign(
                        _uiState.value.plaintext.toByteArray(Charsets.UTF_8),
                        armored,
                        passphrase,
                    )
                }
                maybeUpgradeSecretProtection(keyId, armored, passphrase)
                _uiState.value = _uiState.value.copy(
                    output = String(result.output, Charsets.UTF_8),
                    error = null,
                )
                wipePassphraseUi()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                SensitiveWiper.wipe(passphrase)
                clearBusy()
            }
        }
    }

    /** Produces a detached binary signature for the selected file. */
    fun signFile() {
        viewModelScope.launch {
            var passphrase: CharArray? = null
            _uiState.value = _uiState.value.copy(outputFileBytes = null, outputFileName = null)
            markBusy()
            try {
                val input = _uiState.value.inputFileBytes ?: error(context.getString(R.string.crypto_pick_file_sign))
                val name = _uiState.value.inputFileName ?: "file.bin"
                val keyId = _uiState.value.secretKeyId ?: error(context.getString(R.string.crypto_select_secret_key))
                val key = keys.value.find { it.masterKeyId == keyId } ?: error(context.getString(R.string.crypto_key_not_found))
                if (!key.isSecret) error(context.getString(R.string.crypto_select_secret_sign))
                val armored = withContext(Dispatchers.IO) {
                    keyRepository.getArmoredSecret(keyId) ?: error(context.getString(R.string.crypto_secret_missing))
                }
                passphrase = passphraseForKey(keyId)
                val result = withContext(Dispatchers.Default) {
                    cryptoOperations.sign(input, armored, passphrase, detachedBinary = true)
                }
                maybeUpgradeSecretProtection(keyId, armored, passphrase)
                val outName = CryptoFileHelper.guessSignatureName(name)
                _uiState.value = _uiState.value.copy(
                    outputFileBytes = result.output,
                    outputFileName = outName,
                    fileStatus = context.getString(R.string.crypto_status_signed_fmt, outName),
                    error = null,
                )
                wipePassphraseUi()
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                SensitiveWiper.wipe(passphrase)
                clearBusy()
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
            markBusy(clearVerify = true)
            try {
                val signed = _uiState.value.signedInput.toByteArray(Charsets.UTF_8)
                val result = verifyIncrementally(signed)
                applyVerifyResult(result)
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                clearBusy()
            }
        }
    }

    /** Verifies a detached signature against the selected signed file. */
    fun verifyFile() {
        viewModelScope.launch {
            markBusy(clearVerify = true)
            try {
                val data = _uiState.value.inputFileBytes ?: error(context.getString(R.string.crypto_pick_signed_file))
                val sig = _uiState.value.signatureFileBytes ?: error(context.getString(R.string.crypto_pick_sig_file))
                val result = verifyIncrementally(sig, message = data, binaryDocument = true)
                applyVerifyResult(result)
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = localizeEngineError(e))
            } finally {
                clearBusy()
            }
        }
    }

    private suspend fun loadPublicKeysParallel(ids: Collection<Long>): List<ByteArray> = coroutineScope {
        ids.map { id ->
            async(Dispatchers.IO) { keyRepository.getArmoredPublic(id) }
        }.awaitAll().filterNotNull()
    }

    private suspend fun verifyIncrementally(
        signed: ByteArray,
        message: ByteArray? = null,
        binaryDocument: Boolean = false,
    ): VerifyResult {
        val publics = withContext(Dispatchers.IO) {
            coroutineScope {
                keys.value.map { key ->
                    async(Dispatchers.IO) { keyRepository.getArmoredPublic(key.masterKeyId) }
                }.awaitAll().filterNotNull()
            }
        }
        if (publics.isEmpty()) {
            return VerifyResult(valid = false, error = context.getString(R.string.crypto_no_matching_public_key))
        }
        return withContext(Dispatchers.Default) {
            cryptoOperations.verify(signed, publics, message = message, binaryDocument = binaryDocument)
        }
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
            fileStatus = if (result.valid) context.getString(R.string.crypto_valid_detached_signature) else result.error,
            error = null,
        )
    }

    private fun requirePassphrase(): CharArray {
        require(passphraseChars.isNotEmpty()) { context.getString(R.string.crypto_enter_passphrase) }
        return passphraseChars.copyOf()
    }

    /**
     * Resolves the OpenPGP passphrase for [keyId].
     * Hardware-managed keys unlock via PIN/biometric (no UI passphrase field).
     * Empty passphrase allowed when an OpenPGP Card session owns [keyId].
     */
    private suspend fun passphraseForKey(keyId: Long): CharArray {
        val summary = keys.value.find { it.masterKeyId == keyId }
        if (summary?.hardwareManagedPassphrase == true) {
            val activity = hostActivity?.get()
                ?: error(context.getString(R.string.crypto_hw_unlock_unavailable))
            return hardwarePassphraseGate.unlockAfterAuth(activity, keyId)
        }
        val card = cryptoOperations.smartCardPort
        if (card.isAvailable() && card.ownsKey(keyId)) {
            return passphraseChars.copyOf()
        }
        return requirePassphrase()
    }

    /** Clears the wipeable passphrase buffer and notifies Compose to reset fields. */
    private fun wipePassphraseUi() {
        SensitiveWiper.wipe(passphraseChars)
        passphraseChars = CharArray(0)
        _uiState.update { it.copy(sensitiveInputEpoch = it.sensitiveInputEpoch + 1) }
    }

    /** Status note when SEIPDv2 was requested but recipients forced MDC negotiation. */
    private fun mdcDegradeStatus(
        requested: MessageIntegrity,
        used: MessageIntegrity,
    ): String? =
        if (requested == MessageIntegrity.SEIPD_V2_AEAD && used == MessageIntegrity.MDC) {
            context.getString(R.string.crypto_status_mdc_degraded)
        } else {
            null
        }

    /** Maps known engine English exceptions to localized UI strings. */
    private fun localizeEngineError(e: Throwable): String {
        val msg = e.message ?: return context.getString(R.string.crypto_err_generic)
        return when {
            msg.contains("do not advertise SEIPDv2", ignoreCase = true) ->
                context.getString(R.string.crypto_err_recipients_no_seipdv2)
            msg.contains("No encryption-capable recipient", ignoreCase = true) ->
                context.getString(R.string.crypto_err_no_encrypt_recipients)
            else -> msg
        }
    }

    /** Rejects encrypt-to recipients marked Never-trusted. */
    private fun requireEncryptableRecipients(ids: Collection<Long>) {
        val blocked = keys.value.filter {
            it.masterKeyId in ids && it.trustLevel == KeySummary.TRUST_NEVER
        }
        require(blocked.isEmpty()) {
            context.getString(R.string.crypto_never_trusted_blocked)
        }
    }
}
