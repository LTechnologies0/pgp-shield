package ltechnologies.onionphone.pgpshield.ui.keys

/**
 * Key discovery: keyserver browse-then-import + WKD lookup.
 */

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeyserverClient
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.data.WkdClient
import ltechnologies.onionphone.pgpshield.engine.KeyRingReader
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveContentWidth
import ltechnologies.onionphone.pgpshield.ui.components.M3ListCard
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyId
import ltechnologies.onionphone.pgpshield.util.SecureScreen

data class KeyserverHit(
    val userId: String?,
    val keyId: Long,
    val fingerprint: String,
    val armored: ByteArray,
    val source: String,
)

data class KeySearchUiState(
    val query: String = "",
    val hits: List<KeyserverHit> = emptyList(),
    val error: String? = null,
    val status: String? = null,
    val isBusy: Boolean = false,
)

@HiltViewModel
class KeySearchViewModel @Inject constructor(
    private val keyserverClient: KeyserverClient,
    private val wkdClient: WkdClient,
    private val keyRepository: KeyRepository,
    private val settingsRepository: SettingsRepository,
) : ViewModel() {
    private val reader = KeyRingReader()
    private val _uiState = MutableStateFlow(KeySearchUiState())
    val uiState: StateFlow<KeySearchUiState> = _uiState.asStateFlow()

    fun setQuery(value: String) {
        _uiState.value = _uiState.value.copy(query = value, error = null)
    }

    /** Fetch only — does not import until [importHit]. */
    fun searchKeyserver() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBusy = true, error = null, hits = emptyList(), status = null)
            try {
                val settings = settingsRepository.current()
                if (!settings.keyserverLookupEnabled) error("Keyserver lookup is disabled in Settings")
                val armored = withContext(Dispatchers.IO) {
                    keyserverClient.fetchKey(settings.keyserverUrl, _uiState.value.query.trim())
                }
                val info = withContext(Dispatchers.Default) {
                    reader.readPublicKeyRing(armored.inputStream())
                }
                _uiState.value = _uiState.value.copy(
                    hits = listOf(
                        KeyserverHit(
                            userId = info.userIds.firstOrNull { it.isPrimary }?.userId
                                ?: info.userIds.firstOrNull()?.userId,
                            keyId = info.masterKeyId,
                            fingerprint = info.fingerprint,
                            armored = armored,
                            source = "keyserver",
                        ),
                    ),
                    status = "Found key — review then import",
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message ?: "Search failed")
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    fun searchWkd() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBusy = true, error = null, hits = emptyList(), status = null)
            try {
                val armored = withContext(Dispatchers.IO) {
                    wkdClient.fetchByEmail(_uiState.value.query.trim())
                }
                val info = withContext(Dispatchers.Default) {
                    reader.readPublicKeyRing(armored.inputStream())
                }
                _uiState.value = _uiState.value.copy(
                    hits = listOf(
                        KeyserverHit(
                            userId = info.userIds.firstOrNull { it.isPrimary }?.userId
                                ?: info.userIds.firstOrNull()?.userId,
                            keyId = info.masterKeyId,
                            fingerprint = info.fingerprint,
                            armored = armored,
                            source = "WKD",
                        ),
                    ),
                    status = "Found via WKD — review then import",
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message ?: "WKD failed")
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    fun importHit(hit: KeyserverHit) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBusy = true, error = null)
            try {
                withContext(Dispatchers.Default) {
                    keyRepository.importKeyRing(hit.armored, secret = false)
                }
                _uiState.value = _uiState.value.copy(status = "Imported ${hit.fingerprint}")
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message ?: "Import failed")
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeySearchScreen(
    onBack: () -> Unit,
    viewModel: KeySearchViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsState()
    var query by remember { mutableStateOf("") }

    SecureScreen {
        ScreenScaffold(
            title = stringResource(R.string.keys_search_title),
            showBack = true,
            onBack = onBack,
        ) { padding ->
            AdaptiveContentWidth(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    Text(
                        stringResource(R.string.keys_search_desc),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    OutlinedTextField(
                        value = query,
                        onValueChange = {
                            query = it
                            viewModel.setQuery(it)
                        },
                        label = { Text(stringResource(R.string.keys_search_query_label)) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp),
                        singleLine = true,
                    )
                    Button(
                        onClick = viewModel::searchKeyserver,
                        enabled = !state.isBusy && query.isNotBlank(),
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                    ) {
                        Text(stringResource(R.string.keys_search_action))
                    }
                    TextButton(
                        onClick = viewModel::searchWkd,
                        enabled = !state.isBusy && query.contains('@'),
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(stringResource(R.string.keys_search_wkd))
                    }
                    if (state.isBusy) {
                        CircularProgressIndicator(modifier = Modifier.padding(16.dp))
                    }
                    state.status?.let {
                        Text(it, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 8.dp))
                    }
                    state.error?.let {
                        Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                    }
                    LazyColumn(modifier = Modifier.padding(top = 8.dp)) {
                        items(state.hits, key = { it.fingerprint }) { hit ->
                            M3ListCard(onClick = { viewModel.importHit(hit) }) {
                                Column(modifier = Modifier.padding(16.dp)) {
                                    Text(hit.userId ?: formatKeyId(hit.keyId), style = MaterialTheme.typography.titleMedium)
                                    Text(hit.fingerprint, style = MaterialTheme.typography.bodySmall)
                                    Text(
                                        "${hit.source} — ${stringResource(R.string.keys_search_import_selected)}",
                                        style = MaterialTheme.typography.labelMedium,
                                        color = MaterialTheme.colorScheme.primary,
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
