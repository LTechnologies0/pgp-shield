package ltechnologies.onionphone.pgpshield.ui.keys

/**
 * Compose UI for generating a new OpenPGP key pair, collecting the user id,
 * passphrase and algorithm selection.
 */

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.stringResource
import ltechnologies.onionphone.pgpshield.R
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import ltechnologies.onionphone.pgpshield.engine.AlgorithmLabels
import ltechnologies.onionphone.pgpshield.engine.KeyAlgorithmType
import ltechnologies.onionphone.pgpshield.engine.PgpAlgorithmPolicy
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveScreenColumn
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.util.SecureScreen

/**
 * Key creation screen.
 *
 * Collects user id, passphrase, algorithm and RSA bit length, then delegates
 * generation to [viewModel].
 *
 * @param onBack invoked to navigate back after success or cancel.
 * @param viewModel backing [KeyListViewModel] (defaults to a Hilt instance).
 */
@OptIn(ExperimentalMaterial3Api::class, ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun CreateKeyScreen(
    onBack: () -> Unit,
    viewModel: KeyListViewModel = hiltViewModel(),
) {
    val error by viewModel.error.collectAsState()
    val loading by viewModel.isLoading.collectAsState()

    SecureScreen {
        var userId by remember { mutableStateOf("") }
        var passphrase by remember { mutableStateOf("") }
        var confirm by remember { mutableStateOf("") }
        var algorithmType by remember { mutableStateOf(KeyAlgorithmType.ED25519) }
        var rsaBits by remember { mutableIntStateOf(3072) }
        var algoMenuExpanded by remember { mutableStateOf(false) }
        var rsaMenuExpanded by remember { mutableStateOf(false) }

        ScreenScaffold(
            title = stringResource(R.string.keys_create),
            showBack = true,
            onBack = onBack,
        ) { padding ->
            AdaptiveScreenColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            ) {
                ExposedDropdownMenuBox(
                    expanded = algoMenuExpanded,
                    onExpandedChange = { algoMenuExpanded = it },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    OutlinedTextField(
                        value = AlgorithmLabels.uiLabel(algorithmType, rsaBits),
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Algorithm") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(algoMenuExpanded) },
                        modifier = Modifier
                            .menuAnchor()
                            .fillMaxWidth(),
                    )
                    ExposedDropdownMenu(
                        expanded = algoMenuExpanded,
                        onDismissRequest = { algoMenuExpanded = false },
                    ) {
                        PgpAlgorithmPolicy.androidGeneratableKeyTypes.forEach { type ->
                            DropdownMenuItem(
                                text = { Text(AlgorithmLabels.uiLabel(type, rsaBits)) },
                                onClick = {
                                    algorithmType = type
                                    algoMenuExpanded = false
                                },
                            )
                        }
                    }
                }
                if (algorithmType == KeyAlgorithmType.RSA) {
                    ExposedDropdownMenuBox(
                        expanded = rsaMenuExpanded,
                        onExpandedChange = { rsaMenuExpanded = it },
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                    ) {
                        OutlinedTextField(
                            value = "RSA $rsaBits",
                            onValueChange = {},
                            readOnly = true,
                            label = { Text("RSA key size") },
                            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(rsaMenuExpanded) },
                            modifier = Modifier
                                .menuAnchor()
                                .fillMaxWidth(),
                        )
                        ExposedDropdownMenu(
                            expanded = rsaMenuExpanded,
                            onDismissRequest = { rsaMenuExpanded = false },
                        ) {
                            PgpAlgorithmPolicy.allowedRsaBits.sorted().forEach { bits ->
                                DropdownMenuItem(
                                    text = { Text("RSA $bits") },
                                    onClick = {
                                        rsaBits = bits
                                        rsaMenuExpanded = false
                                    },
                                )
                            }
                        }
                    }
                }
                OutlinedTextField(
                    value = userId,
                    onValueChange = { userId = it },
                    label = { Text("Name <email@example.com>") },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                )
                OutlinedTextField(
                    value = passphrase,
                    onValueChange = { passphrase = it },
                    label = { Text("Passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions.Default,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                )
                OutlinedTextField(
                    value = confirm,
                    onValueChange = { confirm = it },
                    label = { Text("Confirm passphrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = KeyboardOptions.Default,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                )
                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                }
                Button(
                    onClick = {
                        if (passphrase == confirm && userId.isNotBlank()) {
                            viewModel.createKey(
                                userId,
                                passphrase.toCharArray(),
                                algorithmType,
                                rsaBits,
                                onBack,
                            )
                        }
                    },
                    modifier = Modifier
                        .padding(top = 16.dp)
                        .fillMaxWidth(),
                    enabled = !loading && passphrase == confirm && userId.isNotBlank(),
                ) {
                    if (loading) {
                        LoadingIndicator(modifier = Modifier.padding(end = 8.dp))
                    }
                    Text(
                        if (loading) {
                            "Generating key…"
                        } else {
                            "Generate ${AlgorithmLabels.forKeyType(algorithmType, rsaBits)} key"
                        },
                    )
                }
            }
        }
    }
}
