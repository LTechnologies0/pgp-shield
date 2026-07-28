package ltechnologies.onionphone.pgpshield.ui.keys

/**
 * Compose UI and view model for searching a keyserver and importing selected hits.
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import ltechnologies.onionphone.pgpshield.ui.components.M3ListCard
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
import dagger.hilt.android.lifecycle.HiltViewModel
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.KeyRepository
import ltechnologies.onionphone.pgpshield.data.KeyserverClient
import ltechnologies.onionphone.pgpshield.data.KeyserverSearchHit
import ltechnologies.onionphone.pgpshield.data.SettingsRepository
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveContentWidth
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyId
import ltechnologies.onionphone.pgpshield.util.SecureScreen
import javax.inject.Inject
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope

/** Immutable UI state for the keyserver search screen. */
data class KeySearchUiState(
    val query: String = "",
    val hits: List<KeyserverSearchHit> = emptyList(),
    val error: String? = null,
    val status: String? = null,
    val isBusy: Boolean = false,
    val importingFingerprint: String? = null,
)

/**
 * [ViewModel] that searches keyservers (HKP index / VKS) and imports selected hits.
 */
@HiltViewModel
class KeySearchViewModel @Inject constructor(
    private val keyserverClient: KeyserverClient,
    private val keyRepository: KeyRepository,
    private val settingsRepository: SettingsRepository,
) : ViewModel() {
    private val _uiState = MutableStateFlow(KeySearchUiState())
    val uiState: StateFlow<KeySearchUiState> = _uiState.asStateFlow()

    /** Updates the search query text. */
    fun setQuery(value: String) {
        _uiState.value = _uiState.value.copy(query = value, error = null, status = null)
    }

    /** Lists matching keys from the configured keyserver without importing. */
    fun search() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBusy = true, error = null, hits = emptyList(), status = null)
            try {
                val settings = settingsRepository.current()
                if (!settings.keyserverLookupEnabled) {
                    error("Keyserver lookup is disabled in Settings")
                }
                val hits = withContext(Dispatchers.IO) {
                    keyserverClient.searchKeys(settings.keyserverUrl, _uiState.value.query.trim())
                }
                _uiState.value = _uiState.value.copy(
                    hits = hits,
                    status = if (hits.isEmpty()) "No keys found" else "Found ${hits.size} key(s) — tap Import",
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message ?: "Search failed")
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }

    /** Fetches and imports the public key for [hit]. */
    fun importHit(hit: KeyserverSearchHit) {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(
                isBusy = true,
                error = null,
                importingFingerprint = hit.fingerprint,
            )
            try {
                val settings = settingsRepository.current()
                if (!settings.keyserverLookupEnabled) {
                    error("Keyserver lookup is disabled in Settings")
                }
                val query = when {
                    hit.fingerprint.length >= 40 -> hit.fingerprint.takeLast(40)
                    else -> {
                        val id = hit.keyId
                        if (id != null) "0x${KeyserverClient.keyIdToHex(id)}"
                        else hit.fingerprint
                    }
                }
                val armored = withContext(Dispatchers.IO) {
                    keyserverClient.fetchKey(settings.keyserverUrl, query)
                }
                val info = withContext(Dispatchers.Default) {
                    keyRepository.importKeyRing(armored, secret = false)
                }
                _uiState.value = _uiState.value.copy(
                    status = "Imported ${info.userIds.firstOrNull()?.userId ?: formatKeyId(info.masterKeyId)}",
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message ?: "Import failed")
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false, importingFingerprint = null)
            }
        }
    }
}

/**
 * Keyserver search screen: query → list hits → import selected public key.
 */
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
                Column(Modifier.fillMaxSize()) {
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
                            .padding(top = 8.dp),
                        singleLine = true,
                    )
                    Button(
                        onClick = viewModel::search,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        enabled = query.isNotBlank() && !state.isBusy,
                    ) {
                        if (state.isBusy && state.importingFingerprint == null) {
                            CircularProgressIndicator(
                                modifier = Modifier.padding(end = 8.dp),
                                strokeWidth = 2.dp,
                            )
                        }
                        Text(stringResource(R.string.keys_search_action))
                    }
                    state.error?.let {
                        Text(
                            it,
                            color = MaterialTheme.colorScheme.error,
                            modifier = Modifier.padding(top = 8.dp),
                        )
                    }
                    state.status?.let {
                        Text(
                            it,
                            color = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(top = 8.dp),
                        )
                    }
                    LazyColumn(
                        modifier = Modifier
                            .weight(1f)
                            .padding(top = 8.dp),
                    ) {
                        items(state.hits, key = { it.fingerprint }) { hit ->
                            M3ListCard(
                                onClick = null,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(vertical = 4.dp),
                            ) {
                                Column(Modifier.padding(12.dp)) {
                                    Text(
                                        hit.userIds.firstOrNull()
                                            ?: stringResource(R.string.common_unknown),
                                        style = MaterialTheme.typography.titleSmall,
                                    )
                                    hit.keyId?.let {
                                        Text(formatKeyId(it), style = MaterialTheme.typography.bodySmall)
                                    }
                                    Text(hit.fingerprint, style = MaterialTheme.typography.labelSmall)
                                    if (hit.userIds.size > 1) {
                                        Text(
                                            hit.userIds.drop(1).joinToString(" · "),
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                    OutlinedButton(
                                        onClick = { viewModel.importHit(hit) },
                                        enabled = !state.isBusy,
                                        modifier = Modifier
                                            .fillMaxWidth()
                                            .padding(top = 8.dp),
                                    ) {
                                        if (state.importingFingerprint == hit.fingerprint) {
                                            CircularProgressIndicator(
                                                modifier = Modifier.padding(end = 8.dp),
                                                strokeWidth = 2.dp,
                                            )
                                        }
                                        Text(stringResource(R.string.keys_import_title))
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
