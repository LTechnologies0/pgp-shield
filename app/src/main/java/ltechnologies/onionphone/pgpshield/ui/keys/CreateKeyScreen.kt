package ltechnologies.onionphone.pgpshield.ui.keys

/**
 * Compose UI for generating a new OpenPGP key pair, collecting the user id,
 * passphrase and algorithm selection.
 */

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.LoadingIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import ltechnologies.onionphone.pgpshield.engine.KeyFormat
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.res.stringResource
import ltechnologies.onionphone.pgpshield.R
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import ltechnologies.onionphone.pgpshield.engine.AlgorithmLabels
import ltechnologies.onionphone.pgpshield.engine.CryptoStage
import ltechnologies.onionphone.pgpshield.engine.KeyAlgorithmType
import ltechnologies.onionphone.pgpshield.engine.PgpAlgorithmPolicy
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveScreenColumn
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.crypto.CryptoProgressLabels
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
    val cryptoProgress by viewModel.cryptoProgress.collectAsState()
    val context = LocalContext.current

    SecureScreen {
        var userId by remember { mutableStateOf("") }
        var passphrase by remember { mutableStateOf("") }
        var confirm by remember { mutableStateOf("") }
        var hardwareManagedPassphrase by remember { mutableStateOf(false) }
        var algorithmType by remember { mutableStateOf(KeyAlgorithmType.ED25519) }
        var rsaBits by remember { mutableIntStateOf(3072) }
        var algoMenuExpanded by remember { mutableStateOf(false) }
        var rsaMenuExpanded by remember { mutableStateOf(false) }
        var useV6 by remember { mutableStateOf(false) }
        var expiryYears by remember { mutableStateOf("") }
        val hwPassAvailable = remember { viewModel.hardwarePassphraseAvailable() }
        val activity = context as? androidx.fragment.app.FragmentActivity
        // Prefer StrongBox-managed passphrase whenever the enclave is available.
        androidx.compose.runtime.LaunchedEffect(hwPassAvailable) {
            if (hwPassAvailable) hardwareManagedPassphrase = true
        }

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
                    Text(
                        "RSA generates three large primes (sign + encrypt + auth). " +
                            "On a phone this often takes 20–90s — prefer Curve25519 for speed.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                } else {
                    Text(
                        "Curve keys are near-instant; passphrase wrapping still takes a few seconds.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
                OutlinedTextField(
                    value = userId,
                    onValueChange = { userId = it },
                    label = { Text("Name <email@example.com>") },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                )
                if (hwPassAvailable) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 12.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(stringResource(R.string.create_key_hardware_passphrase))
                            Text(
                                stringResource(R.string.create_key_hardware_passphrase_subtitle),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }
                        Switch(
                            checked = hardwareManagedPassphrase,
                            onCheckedChange = {
                                hardwareManagedPassphrase = it
                                if (it) {
                                    passphrase = ""
                                    confirm = ""
                                }
                            },
                        )
                    }
                }
                if (!hardwareManagedPassphrase) {
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
                } else {
                    Text(
                        stringResource(R.string.create_key_hardware_passphrase_active),
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(top = 8.dp),
                    )
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text("OpenPGP v6 key (RFC 9580)")
                        Text(
                            "Native Ed25519/X25519 tags; limited OpenKeychain interop",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(checked = useV6, onCheckedChange = { useV6 = it })
                }
                var useNativeTags by remember { mutableStateOf(false) }
                if (!useV6 && algorithmType == KeyAlgorithmType.ED25519) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(top = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(stringResource(R.string.create_key_native_tags), modifier = Modifier.weight(1f))
                        Switch(checked = useNativeTags, onCheckedChange = { useNativeTags = it })
                    }
                }
                val pqcSupported = remember {
                    ltechnologies.onionphone.pgpshield.engine.PqcSupport.isGenerationSupported
                }
                var experimentalPqc by remember { mutableStateOf(false) }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.create_key_pqc_experimental))
                        Text(
                            if (pqcSupported) {
                                stringResource(R.string.create_key_pqc_experimental)
                            } else {
                                stringResource(R.string.pqc_unavailable)
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    Switch(
                        checked = experimentalPqc && pqcSupported,
                        onCheckedChange = { if (pqcSupported) experimentalPqc = it },
                        enabled = pqcSupported,
                    )
                }
                OutlinedTextField(
                    value = expiryYears,
                    onValueChange = { expiryYears = it.filter { ch -> ch.isDigit() } },
                    label = { Text("Expiry (years, empty = none)") },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                )
                error?.let {
                    Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(top = 8.dp))
                }
                if (loading) {
                    val stage = cryptoProgress?.stage ?: CryptoStage.PREPARE
                    val progress = cryptoProgress?.progress ?: 0.05f
                    Column(modifier = Modifier.fillMaxWidth().padding(top = 12.dp)) {
                        Text(
                            stringResource(R.string.crypto_progress_title),
                            style = MaterialTheme.typography.labelLarge,
                        )
                        Spacer(modifier = Modifier.height(6.dp))
                        LinearProgressIndicator(
                            progress = { progress.coerceIn(0f, 1f) },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text(
                            CryptoProgressLabels.stageLabel(context, stage),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 6.dp),
                        )
                        cryptoProgress?.let { snap ->
                            Text(
                                stringResource(R.string.crypto_progress_elapsed_fmt, snap.elapsedMs),
                                style = MaterialTheme.typography.labelSmall,
                                color = MaterialTheme.colorScheme.outline,
                                modifier = Modifier.padding(top = 2.dp),
                            )
                        }
                    }
                }
                Button(
                    onClick = {
                        val canCreate = userId.isNotBlank() &&
                            (hardwareManagedPassphrase || passphrase == confirm)
                        if (canCreate) {
                            val years = expiryYears.toLongOrNull()
                            val expirySeconds = if (years != null && years > 0) years * 365L * 24L * 3600L else 0L
                            val passChars = if (hardwareManagedPassphrase) {
                                CharArray(0)
                            } else {
                                passphrase.toCharArray()
                            }
                            passphrase = ""
                            confirm = ""
                            viewModel.createKey(
                                userId,
                                passChars,
                                algorithmType,
                                rsaBits,
                                onBack,
                                keyFormat = if (useV6) KeyFormat.V6 else KeyFormat.V4,
                                expirySeconds = expirySeconds,
                                preferNativeCurveTags = useNativeTags,
                                experimentalPqc = experimentalPqc,
                                hardwareManagedPassphrase = hardwareManagedPassphrase,
                                activity = activity,
                            )
                        }
                    },
                    modifier = Modifier
                        .padding(top = 16.dp)
                        .fillMaxWidth(),
                    enabled = !loading && userId.isNotBlank() &&
                        (hardwareManagedPassphrase || passphrase == confirm) &&
                        (!hardwareManagedPassphrase || activity != null),
                ) {
                    if (loading) {
                        LoadingIndicator(modifier = Modifier.padding(end = 8.dp))
                    }
                    Text(
                        if (loading) {
                            if (algorithmType == KeyAlgorithmType.RSA) {
                                "Generating RSA keys (can take up to a minute)…"
                            } else {
                                "Generating key…"
                            }
                        } else {
                            "Generate ${AlgorithmLabels.forKeyType(algorithmType, rsaBits)} key"
                        },
                    )
                }
            }
        }
    }
}
