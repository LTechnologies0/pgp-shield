package ltechnologies.onionphone.pgpshield.ui.components

/**
 * Field and dialog for selecting multiple recipient keys at once.
 */

import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.KeySummary

/**
 * Read-only field summarizing selected keys that opens a multi-select picker.
 *
 * @param selectedIds The currently selected master key ids.
 * @param onSelectionChange Invoked with the new selection when confirmed.
 * @param keyFilter Restricts which keys are selectable.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyMultiSelectField(
    label: String,
    keys: List<KeySummary>,
    selectedIds: Set<Long>,
    onSelectionChange: (Set<Long>) -> Unit,
    modifier: Modifier = Modifier,
    keyFilter: (KeySummary) -> Boolean = { true },
    lineFormatter: (KeySummary) -> String = ::formatKeySummaryLine,
) {
    var showPicker by remember { mutableStateOf(false) }
    val visibleKeys = remember(keys, keyFilter) { keys.filter(keyFilter) }
    val fieldValue = when {
        selectedIds.isEmpty() -> stringResource(R.string.common_select_key)
        selectedIds.size == 1 -> {
            visibleKeys.find { it.masterKeyId in selectedIds }?.let(lineFormatter)
                ?: stringResource(R.string.common_select_key)
        }
        else -> stringResource(R.string.key_picker_count_fmt, selectedIds.size)
    }
    val openPicker = { showPicker = true }

    BoxClickToOpen(
        modifier = modifier.fillMaxWidth(),
        onClick = openPicker,
    ) {
        OutlinedTextField(
            value = fieldValue,
            onValueChange = {},
            readOnly = true,
            enabled = false,
            label = { Text(label) },
            trailingIcon = {
                ExposedDropdownMenuDefaults.TrailingIcon(expanded = showPicker)
            },
            modifier = Modifier.fillMaxWidth(),
        )
    }

    LaunchedEffect(showPicker) {
        if (showPicker) {
            // #region agent log
            ltechnologies.onionphone.pgpshield.util.DebugAgentLog.log(
                location = "KeyMultiSelectPicker.kt:KeyMultiSelectField",
                message = "key picker opened",
                data = mapOf("keyCount" to visibleKeys.size, "selectedCount" to selectedIds.size),
                hypothesisId = "D",
            )
            // #endregion
        }
    }

    KeyMultiSelectSheet(
        visible = showPicker,
        title = label,
        keys = visibleKeys,
        initialSelection = selectedIds,
        onDismiss = { showPicker = false },
        onConfirm = { selection ->
            onSelectionChange(selection)
            showPicker = false
        },
    )
}

/** Transparent overlay so read-only fields reliably receive taps (including inside scroll parents). */
@Composable
private fun BoxClickToOpen(
    modifier: Modifier = Modifier,
    onClick: () -> Unit,
    content: @Composable () -> Unit,
) {
    Box(modifier = modifier) {
        content()
        Box(
            modifier = Modifier
                .matchParentSize()
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = null,
                    onClick = onClick,
                ),
        )
    }
}

/**
 * Searchable dialog listing [keys] with checkboxes for multi-selection.
 *
 * Renders nothing when [visible] is `false`.
 *
 * @param initialSelection Selection to seed the draft state with.
 * @param onConfirm Invoked with the final selection when confirmed.
 */
@Composable
fun KeyMultiSelectSheet(
    visible: Boolean,
    title: String,
    keys: List<KeySummary>,
    initialSelection: Set<Long>,
    onDismiss: () -> Unit,
    onConfirm: (Set<Long>) -> Unit,
) {
    if (!visible) return
    var draft by remember(visible, initialSelection) { mutableStateOf(initialSelection) }
    var query by remember(visible) { mutableStateOf("") }
    val filtered = remember(keys, query) {
        if (query.isBlank()) keys
        else keys.filter { key ->
            val line = "${key.primaryUserId} ${formatKeyId(key.masterKeyId)} ${key.fingerprint}"
            line.contains(query, ignoreCase = true)
        }
    }

    Dialog(onDismissRequest = onDismiss) {
        Surface(
            shape = MaterialTheme.shapes.extraLarge,
            tonalElevation = 6.dp,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(title, style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    label = { Text(stringResource(R.string.keys_search_keyserver)) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 12.dp),
                    singleLine = true,
                )
                if (keys.isEmpty()) {
                    Text(
                        stringResource(R.string.crypto_no_keys),
                        modifier = Modifier.padding(vertical = 16.dp),
                    )
                } else {
                    LazyColumn(modifier = Modifier.heightIn(max = 420.dp)) {
                        items(filtered, key = { it.masterKeyId }) { key ->
                            val checked = key.masterKeyId in draft
                            ListItem(
                                headlineContent = {
                                    Text(
                                        key.primaryUserId ?: stringResource(R.string.common_unknown),
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                },
                                supportingContent = {
                                    Text(
                                        formatKeySummaryLine(key),
                                        maxLines = 2,
                                        overflow = TextOverflow.Ellipsis,
                                    )
                                },
                                leadingContent = {
                                    Checkbox(
                                        checked = checked,
                                        onCheckedChange = {
                                            draft = if (checked) {
                                                draft - key.masterKeyId
                                            } else {
                                                draft + key.masterKeyId
                                            }
                                        },
                                    )
                                },
                                modifier = Modifier.clickable {
                                    draft = if (checked) {
                                        draft - key.masterKeyId
                                    } else {
                                        draft + key.masterKeyId
                                    }
                                },
                            )
                        }
                    }
                }
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    TextButton(onClick = onDismiss, modifier = Modifier.weight(1f)) {
                        Text(stringResource(R.string.common_close))
                    }
                    Button(
                        onClick = { onConfirm(draft) },
                        enabled = draft.isNotEmpty(),
                        modifier = Modifier.weight(1f),
                    ) {
                        Text(stringResource(R.string.key_picker_done))
                    }
                }
            }
        }
    }
}

/**
 * Legacy always-visible wrapper around [KeyMultiSelectSheet].
 *
 * @deprecated Use [KeyMultiSelectSheet], which controls visibility via a flag.
 */
@Composable
fun KeyMultiSelectDialog(
    title: String,
    keys: List<KeySummary>,
    initialSelection: Set<Long>,
    onDismiss: () -> Unit,
    onConfirm: (Set<Long>) -> Unit,
) {
    KeyMultiSelectSheet(
        visible = true,
        title = title,
        keys = keys,
        initialSelection = initialSelection,
        onDismiss = onDismiss,
        onConfirm = onConfirm,
    )
}
