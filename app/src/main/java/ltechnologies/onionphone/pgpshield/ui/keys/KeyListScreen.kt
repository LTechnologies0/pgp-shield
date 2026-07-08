package ltechnologies.onionphone.pgpshield.ui.keys

/**
 * Compose UI for the key list screen, showing secret and public keys with
 * create/import/search entry points and adaptive list/grid layout.
 */

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.KeySummary
import ltechnologies.onionphone.pgpshield.ui.components.AdaptiveContentWidth
import ltechnologies.onionphone.pgpshield.ui.components.ScreenScaffold
import ltechnologies.onionphone.pgpshield.ui.components.AlgorithmChip
import ltechnologies.onionphone.pgpshield.ui.components.ChipRow
import ltechnologies.onionphone.pgpshield.ui.components.EmptyState
import ltechnologies.onionphone.pgpshield.ui.components.KeyAvatar
import ltechnologies.onionphone.pgpshield.ui.components.M3ListCard
import ltechnologies.onionphone.pgpshield.ui.components.RevokedBadge
import ltechnologies.onionphone.pgpshield.ui.components.SectionHeader
import ltechnologies.onionphone.pgpshield.ui.components.WindowLayout
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyDate
import ltechnologies.onionphone.pgpshield.ui.components.formatKeyId
import ltechnologies.onionphone.pgpshield.ui.components.formatShortFingerprint
import ltechnologies.onionphone.pgpshield.ui.components.rememberAdaptiveMetrics

/**
 * Key list screen listing the user's secret and public keys.
 *
 * @param onCreateKey invoked to start key creation.
 * @param onImportKey invoked to start key import.
 * @param onSearchKeys invoked to open keyserver search.
 * @param onKeyClick invoked with a master key id when a key row is tapped.
 * @param showTopBar whether to render the screen's top app bar.
 * @param viewModel backing [KeyListViewModel] (defaults to a Hilt instance).
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyListScreen(
    onCreateKey: () -> Unit,
    onImportKey: () -> Unit,
    onSearchKeys: () -> Unit,
    onKeyClick: (Long) -> Unit,
    showTopBar: Boolean = true,
    viewModel: KeyListViewModel = hiltViewModel(),
) {
    val keys by viewModel.keys.collectAsStateWithLifecycle()
    val showFingerprint by viewModel.showFingerprintOnList.collectAsStateWithLifecycle()
    val metrics = rememberAdaptiveMetrics()
    val useGrid = metrics.layout != WindowLayout.Compact
    val secretKeys = remember(keys) { keys.filter { it.isSecret } }
    val publicKeys = remember(keys) { keys.filter { !it.isSecret } }
    var showAddSheet by remember { mutableStateOf(false) }

    ScreenScaffold(
        title = stringResource(R.string.keys_title),
        actions = {
            IconButton(onClick = onSearchKeys) {
                Icon(
                    Icons.Default.Search,
                    contentDescription = stringResource(R.string.keys_search_keyserver),
                )
            }
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddSheet = true }) {
                Icon(Icons.Default.Add, contentDescription = stringResource(R.string.keys_add_key))
            }
        },
    ) { padding ->
        if (keys.isEmpty()) {
            EmptyState(
                message = stringResource(R.string.keys_empty),
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            )
        } else {
            AdaptiveContentWidth(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
            ) {
                if (useGrid) {
                    val cellMin = metrics.listMinCellWidth
                    LazyVerticalGrid(
                        columns = GridCells.Adaptive(minSize = cellMin),
                        contentPadding = PaddingValues(
                            top = metrics.sectionSpacing,
                            bottom = 88.dp,
                        ),
                        horizontalArrangement = Arrangement.spacedBy(metrics.sectionSpacing),
                        verticalArrangement = Arrangement.spacedBy(metrics.sectionSpacing),
                    ) {
                        if (secretKeys.isNotEmpty()) {
                            item(span = { GridItemSpan(maxLineSpan) }) {
                                SectionHeader(stringResource(R.string.keys_section_secret))
                            }
                            items(secretKeys, key = { it.masterKeyId }) { key ->
                                KeyRow(
                                    key = key,
                                    showFingerprint = showFingerprint,
                                    onClick = { onKeyClick(key.masterKeyId) },
                                    large = metrics.layout == WindowLayout.Expanded,
                                )
                            }
                        }
                        if (publicKeys.isNotEmpty()) {
                            item(span = { GridItemSpan(maxLineSpan) }) {
                                SectionHeader(stringResource(R.string.keys_section_public))
                            }
                            items(publicKeys, key = { it.masterKeyId }) { key ->
                                KeyRow(
                                    key = key,
                                    showFingerprint = showFingerprint,
                                    onClick = { onKeyClick(key.masterKeyId) },
                                    large = metrics.layout == WindowLayout.Expanded,
                                )
                            }
                        }
                    }
                } else {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(
                            top = metrics.sectionSpacing,
                            bottom = 88.dp,
                        ),
                        verticalArrangement = Arrangement.spacedBy(metrics.sectionSpacing),
                    ) {
                        if (secretKeys.isNotEmpty()) {
                            item { SectionHeader(stringResource(R.string.keys_section_secret)) }
                            items(secretKeys, key = { it.masterKeyId }) { key ->
                                KeyRow(
                                    key = key,
                                    showFingerprint = showFingerprint,
                                    onClick = { onKeyClick(key.masterKeyId) },
                                )
                            }
                        }
                        if (publicKeys.isNotEmpty()) {
                            item { SectionHeader(stringResource(R.string.keys_section_public)) }
                            items(publicKeys, key = { it.masterKeyId }) { key ->
                                KeyRow(
                                    key = key,
                                    showFingerprint = showFingerprint,
                                    onClick = { onKeyClick(key.masterKeyId) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    if (showAddSheet) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { showAddSheet = false },
            sheetState = sheetState,
        ) {
            Column(modifier = Modifier.padding(bottom = 24.dp)) {
                Text(
                    stringResource(R.string.keys_add_key),
                    style = MaterialTheme.typography.titleLarge,
                    modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp),
                )
                ListItem(
                    headlineContent = { Text(stringResource(R.string.keys_create)) },
                    modifier = Modifier.clickable {
                        showAddSheet = false
                        onCreateKey()
                    },
                )
                ListItem(
                    headlineContent = { Text(stringResource(R.string.keys_import)) },
                    modifier = Modifier.clickable {
                        showAddSheet = false
                        onImportKey()
                    },
                )
            }
        }
    }
}

@Composable
private fun KeyRow(
    key: KeySummary,
    showFingerprint: Boolean,
    onClick: () -> Unit,
    large: Boolean = false,
) {
    M3ListCard(onClick = onClick) {
        Row(
            Modifier.padding(if (large) 20.dp else 16.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            KeyAvatar(key.primaryUserId, large = large)
            Column(Modifier.padding(start = 12.dp).weight(1f)) {
                Text(
                    key.primaryUserId ?: stringResource(R.string.common_unknown),
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(
                    formatKeyId(key.masterKeyId),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                )
                if (showFingerprint) {
                    Text(
                        formatShortFingerprint(key.fingerprint),
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(stringResource(R.string.keys_created_fmt, formatKeyDate(key.createdAt)), style = MaterialTheme.typography.labelSmall)
                ChipRow(modifier = Modifier.padding(top = 4.dp)) {
                    AlgorithmChip(key.primaryAlgorithm)
                    if (key.isSecret) {
                        AlgorithmChip(stringResource(R.string.keys_secret))
                    } else {
                        AlgorithmChip(stringResource(R.string.keys_public))
                    }
                    if (key.isRevoked) {
                        RevokedBadge()
                    }
                }
            }
        }
    }
}
