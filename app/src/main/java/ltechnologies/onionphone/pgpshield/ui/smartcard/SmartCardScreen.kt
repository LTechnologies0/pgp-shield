package ltechnologies.onionphone.pgpshield.ui.smartcard

import android.app.Activity
import android.nfc.NfcAdapter
import android.nfc.Tag
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.engine.OpenPgpCardInfo
import ltechnologies.onionphone.pgpshield.security.FidoAppLockManager
import ltechnologies.onionphone.pgpshield.smartcard.OpenPgpCardNfcPort
import ltechnologies.onionphone.pgpshield.smartcard.OpenPgpCardUsbPort
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.SectionHeader
import ltechnologies.onionphone.pgpshield.util.SecureScreen
import ltechnologies.onionphone.pgpshield.util.SensitiveWiper
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

enum class TokenStep { PRESENT, HOLD, DONE }

data class SmartCardUiState(
    val step: TokenStep = TokenStep.PRESENT,
    val available: Boolean = false,
    val info: OpenPgpCardInfo? = null,
    /** Increments when the PIN buffer is wiped so Compose TextFields can reset. */
    val sensitiveInputEpoch: Long = 0L,
    val status: String? = null,
    val error: String? = null,
    val fidoEnabled: Boolean = false,
    val fidoLabel: String? = null,
    val usbCandidates: Int = 0,
)

@HiltViewModel
class SmartCardViewModel @Inject constructor(
    private val cryptoOperations: CryptoOperations,
    private val keyRepository: KeyRepository,
    private val nfcPort: OpenPgpCardNfcPort,
    private val usbPort: OpenPgpCardUsbPort,
    private val fido: FidoAppLockManager,
) : ViewModel() {
    private val _ui = MutableStateFlow(
        SmartCardUiState(
            available = cryptoOperations.smartCardPort.isAvailable(),
            fidoEnabled = fido.current().enabled,
            fidoLabel = fido.current().credentialLabel,
            usbCandidates = usbPort.listCandidateDevices().size,
        ),
    )
    val uiState: StateFlow<SmartCardUiState> = _ui.asStateFlow()

    /** Wipeable PIN buffer — source of truth for verify (not the UI String copy). */
    private var pinChars: CharArray = CharArray(0)

    /** Updates the PIN CharArray buffer (Compose keeps TextField state locally). */
    fun setPin(value: String) {
        SensitiveWiper.wipe(pinChars)
        pinChars = value.toCharArray()
        _ui.value = _ui.value.copy(error = null)
    }

    /** Clears the PIN buffer and notifies Compose to reset the field. */
    fun clearPin() {
        SensitiveWiper.wipe(pinChars)
        pinChars = CharArray(0)
        _ui.value = _ui.value.copy(sensitiveInputEpoch = _ui.value.sensitiveInputEpoch + 1)
    }

    fun onNfcTag(tag: Tag) {
        viewModelScope.launch {
            _ui.value = _ui.value.copy(step = TokenStep.HOLD, error = null, status = "Reading card...")
            runCatching {
                val info = nfcPort.attachTag(tag)
                _ui.value = _ui.value.copy(
                    available = true,
                    info = info,
                    status = "Card selected (" + info.transport + "). Enter PIN.",
                )
            }.onFailure {
                _ui.value = _ui.value.copy(step = TokenStep.PRESENT, error = it.message, status = null)
            }
        }
    }

    fun connectUsb() {
        viewModelScope.launch {
            val device = usbPort.listCandidateDevices().firstOrNull()
            if (device == null) {
                _ui.value = _ui.value.copy(error = "No USB CCID device found (OTG required)")
                return@launch
            }
            _ui.value = _ui.value.copy(step = TokenStep.HOLD, status = "Requesting USB permission...")
            val permitted = suspendCancellableCoroutine { cont ->
                usbPort.requestPermission(
                    device,
                    onGranted = { cont.resume(it) },
                    onDenied = { cont.resume(null) },
                )
            }
            if (permitted == null) {
                _ui.value = _ui.value.copy(error = "USB permission denied", step = TokenStep.PRESENT)
                return@launch
            }
            _ui.value = _ui.value.copy(status = "Opening USB...")
            runCatching {
                val info = usbPort.attachDevice(permitted)
                _ui.value = _ui.value.copy(
                    available = true,
                    info = info,
                    status = "USB card ready. Enter PIN.",
                    usbCandidates = usbPort.listCandidateDevices().size,
                )
            }.onFailure {
                _ui.value = _ui.value.copy(error = it.message, step = TokenStep.PRESENT)
            }
        }
    }

    fun verifyPin() {
        viewModelScope.launch {
            val pinCopy = pinChars.copyOf()
            try {
                require(pinCopy.size >= 6) { "PIN too short" }
                val ok = cryptoOperations.smartCardPort.verifyPin(pinCopy)
                if (ok) {
                    val boundIds = withContext(Dispatchers.IO) {
                        val reader = ltechnologies.onionphone.pgpshield.engine.KeyRingReader()
                        val ids = linkedSetOf<Long>()
                        for (summary in keyRepository.search("").filter { it.isSecret }) {
                            ids += summary.masterKeyId
                            val armored = keyRepository.getArmoredSecret(summary.masterKeyId) ?: continue
                            runCatching {
                                val info = reader.readSecretKeyRing(armored.inputStream())
                                ids += info.masterKeyId
                                info.subkeys.forEach { ids += it.keyId }
                            }
                        }
                        ids
                    }
                    cryptoOperations.smartCardPort.bindKeyIds(boundIds)
                    clearPin()
                    _ui.value = _ui.value.copy(
                        step = TokenStep.DONE,
                        status = "PIN OK — ${boundIds.size} key id(s) bound to card. You can remove the token after use.",
                        error = null,
                    )
                } else {
                    clearPin()
                    _ui.value = _ui.value.copy(error = "PIN rejected", step = TokenStep.HOLD)
                }
            } catch (e: Exception) {
                clearPin()
                _ui.value = _ui.value.copy(error = e.message ?: "PIN verify failed", step = TokenStep.HOLD)
            } finally {
                SensitiveWiper.wipe(pinCopy)
            }
        }
    }

    fun toggleFido(enabled: Boolean) {
        fido.setEnabled(enabled)
        _ui.value = _ui.value.copy(fidoEnabled = fido.current().enabled, fidoLabel = fido.current().credentialLabel)
    }

    fun closeSession() {
        cryptoOperations.smartCardPort.close()
        clearPin()
        _ui.value = _ui.value.copy(
            step = TokenStep.PRESENT,
            available = false,
            info = null,
            status = "Session closed",
        )
    }

    override fun onCleared() {
        SensitiveWiper.wipe(pinChars)
        pinChars = CharArray(0)
        super.onCleared()
    }
}

@Composable
fun SmartCardScreen(
    onBack: () -> Unit,
    viewModel: SmartCardViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current
    val activity = context as? Activity
    var pinField by remember { mutableStateOf("") }
    var pinReady by remember { mutableStateOf(false) }

    LaunchedEffect(state.sensitiveInputEpoch) {
        pinField = ""
        pinReady = false
    }

    DisposableEffect(activity) {
        val adapter = NfcAdapter.getDefaultAdapter(context)
        if (activity != null && adapter != null) {
            adapter.enableReaderMode(
                activity,
                { tag -> viewModel.onNfcTag(tag) },
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
                null,
            )
        }
        onDispose {
            if (activity != null && adapter != null) {
                runCatching { adapter.disableReaderMode(activity) }
            }
            viewModel.clearPin()
        }
    }

    SecureScreen {
        ScreenScaffold(
            title = stringResource(R.string.smartcard_title),
            showBack = true,
            onBack = onBack,
            content = { padding ->
                Column(
                    Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .padding(horizontal = 16.dp)
                        .verticalScroll(rememberScrollState()),
                ) {
                    SectionHeader(stringResource(R.string.smartcard_hardware_tokens))
                    TokenStepCard(state.step)
                    val infoText = state.info?.let {
                        "AID ${it.aid}\nSerial ${it.serial ?: "-"}\nTransport ${it.transport}\n" +
                            "Sign=${it.hasSignKey} Decrypt=${it.hasDecryptKey} Auth=${it.hasAuthKey}"
                    } ?: stringResource(R.string.smartcard_waiting_nfc)
                    Text(
                        text = infoText,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(top = 12.dp),
                    )
                    OutlinedTextField(
                        value = pinField,
                        onValueChange = {
                            pinField = it
                            viewModel.setPin(it)
                            pinReady = it.length >= 6
                        },
                        label = { Text(stringResource(R.string.smartcard_pin)) },
                        visualTransformation = PasswordVisualTransformation(),
                        modifier = Modifier.fillMaxWidth().padding(top = 12.dp),
                        singleLine = true,
                    )
                    Button(
                        onClick = viewModel::verifyPin,
                        enabled = state.available && pinReady,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    ) { Text(stringResource(R.string.smartcard_verify_pin)) }
                    Button(
                        onClick = viewModel::connectUsb,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    ) { Text(stringResource(R.string.smartcard_connect_usb_fmt, state.usbCandidates)) }
                    Button(
                        onClick = viewModel::closeSession,
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    ) { Text(stringResource(R.string.smartcard_close_session)) }
                    SectionHeader(stringResource(R.string.smartcard_fido_section))
                    Button(
                        onClick = { viewModel.toggleFido(!state.fidoEnabled) },
                        modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                    ) {
                        Text(
                            stringResource(
                                if (state.fidoEnabled) R.string.smartcard_fido_on_fmt else R.string.smartcard_fido_off,
                                state.fidoLabel ?: "",
                            ),
                        )
                    }
                    Text(
                        stringResource(R.string.smartcard_fido_help),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 4.dp),
                    )
                    state.status?.let { msg ->
                        Text(msg, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
                    }
                    state.error?.let { msg ->
                        Text(msg, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                    }
                }
            },
        )
    }
}

@Composable
private fun TokenStepCard(step: TokenStep) {
    val title = when (step) {
        TokenStep.PRESENT -> stringResource(R.string.smartcard_step1_title)
        TokenStep.HOLD -> stringResource(R.string.smartcard_step2_title)
        TokenStep.DONE -> stringResource(R.string.smartcard_step3_title)
    }
    val body = when (step) {
        TokenStep.PRESENT -> stringResource(R.string.smartcard_step1_body)
        TokenStep.HOLD -> stringResource(R.string.smartcard_step2_body)
        TokenStep.DONE -> stringResource(R.string.smartcard_step3_body)
    }
    Text(title, style = MaterialTheme.typography.titleMedium, modifier = Modifier.padding(top = 8.dp))
    Text(body, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(top = 4.dp))
}
