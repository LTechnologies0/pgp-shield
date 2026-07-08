package ltechnologies.onionphone.pgpshield.ui.components

/**
 * Reusable modal surfaces: a form bottom sheet and a destructive confirm dialog.
 */

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.BasicAlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import ltechnologies.onionphone.pgpshield.R

/**
 * Modal bottom sheet presenting a titled form with confirm/close actions.
 *
 * Renders nothing when [visible] is `false`.
 *
 * @param confirmEnabled Enables/disables the confirm button.
 * @param content The form body laid out in a column.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FormBottomSheet(
    visible: Boolean,
    title: String,
    onDismiss: () -> Unit,
    confirmLabel: String,
    onConfirm: () -> Unit,
    confirmEnabled: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    if (!visible) return
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleLarge)
            content()
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp, bottom = 32.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.common_close))
                }
                TextButton(onClick = onConfirm, enabled = confirmEnabled) {
                    Text(confirmLabel)
                }
            }
        }
    }
}

/**
 * Confirmation dialog for destructive actions (delete, revoke, etc.).
 *
 * Renders nothing when [visible] is `false`.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DestructiveConfirmDialog(
    visible: Boolean,
    title: String,
    message: String,
    confirmLabel: String,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    if (!visible) return
    BasicAlertDialog(onDismissRequest = onDismiss) {
        Column(modifier = Modifier.padding(24.dp)) {
            Text(title, style = MaterialTheme.typography.titleLarge)
            Text(
                message,
                style = MaterialTheme.typography.bodyMedium,
                modifier = Modifier.padding(top = 12.dp),
            )
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 24.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.common_close))
                }
                TextButton(onClick = onConfirm) {
                    Text(confirmLabel)
                }
            }
        }
    }
}
