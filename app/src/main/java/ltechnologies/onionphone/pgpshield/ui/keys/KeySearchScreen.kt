package ltechnologies.onionphone.pgpshield.ui.keys

/**
 * Compose UI and view model for searching a keyserver and importing the
 * resulting public key.
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

/** A single key result returned from a keyserver lookup. */
data class KeyserverHit(
    val userId: String?,
    val keyId: Long,
    val fingerprint: String,
)

/** Immutable UI state for the keyserver search screen. */
data class KeySearchUiState(
    val query: String = "",
    val hits: List<KeyserverHit> = emptyList(),
    val error: String? = null,
    val status: String? = null,
    val isBusy: Boolean = false,
)

/**
 * [ViewModel] that performs keyserver lookups and imports the fetched public key
 * into the local repository.
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
        _uiState.value = _uiState.value.copy(query = value, error = null)
    }

    /** Fetches a key from the configured keyserver and imports it as public. */
    fun search() {
        viewModelScope.launch {
            _uiState.value = _uiState.value.copy(isBusy = true, error = null, hits = emptyList())
            try {
                val settings = settingsRepository.current()
                if (!settings.keyserverLookupEnabled) {
                    error("Keyserver lookup is disabled in Settings")
                }
                val armored = withContext(Dispatchers.IO) {
                    keyserverClient.fetchKey(settings.keyserverUrl, _uiState.value.query.trim())
                }
                val info = withContext(Dispatchers.Default) {
                    keyRepository.importKeyRing(armored, secret = false)
                }
                _uiState.value = _uiState.value.copy(
                    hits = listOf(
                        KeyserverHit(
                            userId = info.userIds.firstOrNull { it.isPrimary }?.userId
                                ?: info.userIds.firstOrNull()?.userId,
                            keyId = info.masterKeyId,
                            fingerprint = info.fingerprint,
                        ),
                    ),
                    status = "Imported public key",
                )
            } catch (e: Exception) {
                _uiState.value = _uiState.value.copy(error = e.message ?: "Search failed")
            } finally {
                _uiState.value = _uiState.value.copy(isBusy = false)
            }
        }
    }
}

/**
 * Keyserver search screen: lets the user query by fingerprint/user id and import
 * the returned public key.
 *
 * @param onBack invoked to navigate back.
 * @param viewModel backing [KeySearchViewModel] (defaults to a Hilt instance).
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
                )
                Button(
                    onClick = viewModel::search,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                    enabled = query.isNotBlank() && !state.isBusy,
                ) {
                    if (state.isBusy) {
                        CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                    }
                    Text(stringResource(R.string.keys_search_action))
                }
                state.error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                }
                state.status?.let {
                    Text(it, color = MaterialTheme.colorScheme.primary, modifier = Modifier.padding(top = 8.dp))
                }
                LazyColumn(
                    modifier = Modifier
                        .weight(1f)
                        .padding(top = 8.dp),
                ) {
                    items(state.hits, key = { it.keyId }) { hit ->
                        M3ListCard(onClick = null, modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
                            Column(Modifier.padding(12.dp)) {
                                Text(hit.userId ?: stringResource(R.string.common_unknown), style = MaterialTheme.typography.titleSmall)
                                Text(formatKeyId(hit.keyId), style = MaterialTheme.typography.bodySmall)
                                Text(hit.fingerprint, style = MaterialTheme.typography.labelSmall)
                            }
                        }
                    }
                }
                }
            }
        }
    }
}
