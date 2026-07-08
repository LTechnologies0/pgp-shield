package ltechnologies.onionphone.pgpshield.ui.smartcard

/**
 * Compose UI and view model for smart-card / hardware-token support status.
 */

import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import ltechnologies.onionphone.pgpshield.crypto.CryptoOperations
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveScreenColumn
import ltechnologies.onionphone.pgpshield.ui.components.M3ListCard
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.SectionHeader
import ltechnologies.onionphone.pgpshield.util.SecureScreen
import androidx.hilt.navigation.compose.hiltViewModel
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

/**
 * [ViewModel] reporting whether a smart-card port is available on this device.
 */
@HiltViewModel
class SmartCardViewModel @Inject constructor(
    cryptoOperations: CryptoOperations,
) : androidx.lifecycle.ViewModel() {
    /** True when the underlying smart-card port reports availability. */
    val available = cryptoOperations.smartCardPort.isAvailable()
}

/**
 * Smart-card status screen (hardware-token integration placeholder).
 *
 * @param onBack invoked to navigate back.
 * @param viewModel backing [SmartCardViewModel].
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SmartCardScreen(
    onBack: () -> Unit,
    viewModel: SmartCardViewModel = hiltViewModel(),
) {
    SecureScreen {
        ScreenScaffold(
            title = stringResource(R.string.smartcard_title),
            showBack = true,
            onBack = onBack,
        ) { padding ->
            AdaptiveScreenColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            ) {
                SectionHeader(stringResource(R.string.smartcard_hardware_tokens))
                M3ListCard(onClick = null) {
                    Text(
                        text = stringResource(R.string.smartcard_stub_desc_fmt, viewModel.available.toString()),
                        modifier = Modifier.padding(16.dp),
                        style = MaterialTheme.typography.bodyMedium,
                    )
                }
                Text(
                    // ponytail: NFC/USB CCID integration deferred until hardware spec settled
                    stringResource(R.string.smartcard_future_desc),
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}
