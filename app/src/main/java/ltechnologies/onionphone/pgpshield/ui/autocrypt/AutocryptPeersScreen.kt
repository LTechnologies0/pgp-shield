package ltechnologies.onionphone.pgpshield.ui.autocrypt

/**
 * Autocrypt peer mapping viewer (Kleopatra-style address book lite).
 */

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.AutocryptManager
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveScreenColumn
import ltechnologies.onionphone.pgpshield.ui.components.M3ListCard
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyId
import ltechnologies.onionphone.pgpshield.util.SecureScreen

@HiltViewModel
class AutocryptViewModel @Inject constructor(
    private val autocryptManager: AutocryptManager,
) : ViewModel() {
    private val _peers = MutableStateFlow(autocryptManager.allMappings().toList())
    val peers: StateFlow<List<Pair<String, Long>>> = _peers.asStateFlow()

    fun refresh() {
        _peers.value = autocryptManager.allMappings().toList()
    }

    fun remove(email: String) {
        autocryptManager.remove(email)
        refresh()
    }
}

@Composable
fun AutocryptPeersScreen(
    onBack: () -> Unit,
    onOpenKey: (Long) -> Unit = {},
    viewModel: AutocryptViewModel = hiltViewModel(),
) {
    val peers by viewModel.peers.collectAsState()
    SecureScreen {
        ScreenScaffold(
            title = stringResource(R.string.autocrypt_title),
            showBack = true,
            onBack = onBack,
        ) { padding ->
            AdaptiveScreenColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            ) {
                OutlinedButton(
                    onClick = viewModel::refresh,
                    modifier = Modifier.fillMaxWidth().padding(bottom = 8.dp),
                ) {
                    Text(stringResource(R.string.autocrypt_refresh))
                }
                if (peers.isEmpty()) {
                    Text(
                        stringResource(R.string.autocrypt_empty),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                } else {
                    LazyColumn(modifier = Modifier.fillMaxWidth()) {
                        items(peers, key = { it.first }) { (email, keyId) ->
                            M3ListCard(onClick = { onOpenKey(keyId) }) {
                                androidx.compose.foundation.layout.Column(
                                    modifier = Modifier.padding(16.dp),
                                ) {
                                    Text(email, style = MaterialTheme.typography.titleMedium)
                                    Text(formatKeyId(keyId), style = MaterialTheme.typography.bodySmall)
                                    OutlinedButton(
                                        onClick = { viewModel.remove(email) },
                                        modifier = Modifier.padding(top = 8.dp),
                                    ) {
                                        Text(stringResource(R.string.autocrypt_remove))
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
