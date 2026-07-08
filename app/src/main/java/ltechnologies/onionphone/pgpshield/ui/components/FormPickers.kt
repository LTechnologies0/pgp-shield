package ltechnologies.onionphone.pgpshield.ui.components

/**
 * Reusable form controls: key/string dropdown pickers and a settings switch row.
 */

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.ListItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.KeySummary

/**
 * Exposed dropdown for selecting a key from [keys].
 *
 * @param selectedId Currently selected master key id, or `null`.
 * @param onSelect Callback with the chosen key id (`null` when "auto" is picked).
 * @param allowAuto Whether to offer an automatic/no-selection entry.
 * @param keyFilter Predicate restricting which keys are shown.
 * @param lineFormatter Formats each key's display line.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeySelectDropdown(
    label: String,
    keys: List<KeySummary>,
    selectedId: Long?,
    onSelect: (Long?) -> Unit,
    modifier: Modifier = Modifier,
    allowAuto: Boolean = false,
    emptyLabel: String = stringResource(R.string.common_select_key),
    autoLabel: String = stringResource(R.string.common_auto),
    keyFilter: (KeySummary) -> Boolean = { true },
    expanded: Boolean? = null,
    onExpandedChange: ((Boolean) -> Unit)? = null,
    lineFormatter: (KeySummary) -> String = { "${it.primaryUserId} (${formatKeyId(it.masterKeyId)})" },
) {
    var internalExpanded by remember { mutableStateOf(false) }
    val menuExpanded = expanded ?: internalExpanded
    val setExpanded: (Boolean) -> Unit = onExpandedChange ?: { internalExpanded = it }
    val visible = remember(keys, keyFilter) { keys.filter(keyFilter) }
    val selected = visible.find { it.masterKeyId == selectedId }
    val display = selected?.let(lineFormatter) ?: emptyLabel

    ExposedDropdownMenuBox(
        expanded = menuExpanded,
        onExpandedChange = setExpanded,
        modifier = modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = display,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(menuExpanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth(),
        )
        ExposedDropdownMenu(expanded = menuExpanded, onDismissRequest = { setExpanded(false) }) {
            if (allowAuto) {
                DropdownMenuItem(
                    text = { Text(autoLabel) },
                    onClick = { onSelect(null); setExpanded(false) },
                )
            }
            visible.forEach { key ->
                DropdownMenuItem(
                    text = { Text(lineFormatter(key)) },
                    onClick = { onSelect(key.masterKeyId); setExpanded(false) },
                )
            }
        }
    }
}

/**
 * Exposed dropdown for selecting one of several string [options].
 *
 * @param value Currently displayed value.
 * @param options List of `(id, title)` pairs; `id` is passed to [onSelect].
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StringSelectDropdown(
    label: String,
    value: String,
    options: List<Pair<String, String>>,
    onSelect: (String) -> Unit,
    modifier: Modifier = Modifier,
    expanded: Boolean? = null,
    onExpandedChange: ((Boolean) -> Unit)? = null,
) {
    var internalExpanded by remember { mutableStateOf(false) }
    val menuExpanded = expanded ?: internalExpanded
    val setExpanded: (Boolean) -> Unit = onExpandedChange ?: { internalExpanded = it }

    ExposedDropdownMenuBox(
        expanded = menuExpanded,
        onExpandedChange = setExpanded,
        modifier = modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(menuExpanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth(),
        )
        ExposedDropdownMenu(expanded = menuExpanded, onDismissRequest = { setExpanded(false) }) {
            options.forEach { (id, title) ->
                DropdownMenuItem(
                    text = { Text(title) },
                    onClick = { onSelect(id); setExpanded(false) },
                )
            }
        }
    }
}

/** List row with a label, optional [subtitle] and a trailing toggle [Switch]. */
@Composable
fun SettingSwitchRow(
    label: String,
    checked: Boolean,
    onChecked: (Boolean) -> Unit,
    modifier: Modifier = Modifier,
    subtitle: String? = null,
) {
    ListItem(
        headlineContent = { Text(label) },
        supportingContent = subtitle?.let { { Text(it) } },
        trailingContent = { Switch(checked = checked, onCheckedChange = onChecked) },
        modifier = modifier
            .fillMaxWidth()
            .clickable { onChecked(!checked) },
    )
}
