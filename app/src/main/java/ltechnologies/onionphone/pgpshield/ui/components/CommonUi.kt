package ltechnologies.onionphone.pgpshield.ui.components

/**
 * Shared Compose building blocks and formatting helpers used across screens.
 */

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Inbox
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.res.stringResource
import ltechnologies.onionphone.pgpshield.R
import ltechnologies.onionphone.pgpshield.data.KeySummary
import java.text.DateFormat
import java.util.Date

/** Ambient [SnackbarHostState] shared by screens for showing snackbars. */
val LocalSnackbarHostState = compositionLocalOf<SnackbarHostState> {
    error("No SnackbarHostState provided")
}

/** A styled section title used to group content within a screen. */
@Composable
fun SectionHeader(title: String, modifier: Modifier = Modifier) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleSmall,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.primary,
        modifier = modifier
            .fillMaxWidth()
            .padding(top = 16.dp, bottom = 4.dp),
    )
}

/** Circular avatar showing the first letter of [name] (or `?` when unknown). */
@Composable
fun KeyAvatar(name: String?, modifier: Modifier = Modifier, large: Boolean = false) {
    val initial = name?.trim()?.firstOrNull()?.uppercaseChar()?.toString() ?: "?"
    val size = if (large) 56.dp else 40.dp
    Box(
        modifier = modifier
            .size(size)
            .clip(CircleShape)
            .background(MaterialTheme.colorScheme.primaryContainer),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            initial,
            style = if (large) MaterialTheme.typography.headlineSmall else MaterialTheme.typography.titleMedium,
        )
    }
}

/** Non-interactive chip displaying a key algorithm [label]. */
@Composable
fun AlgorithmChip(label: String, modifier: Modifier = Modifier) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = {
            Text(label, maxLines = 1, overflow = TextOverflow.Ellipsis)
        },
        modifier = modifier,
    )
}

/** Non-interactive badge marking a key as revoked. */
@Composable
fun RevokedBadge(modifier: Modifier = Modifier) {
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(stringResource(R.string.common_revoked)) },
        modifier = modifier,
    )
}

/** A wrapping [FlowRow] container for laying out a set of chips. */
@OptIn(ExperimentalLayoutApi::class)
@Composable
fun ChipRow(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    FlowRow(
        modifier = modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(4.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
        content = { content() },
    )
}

/** Single-line, horizontally scrollable monospace text (fingerprints, ids). */
@Composable
fun MonospaceScrollText(
    text: String,
    modifier: Modifier = Modifier,
    style: androidx.compose.ui.text.TextStyle = MaterialTheme.typography.bodySmall,
) {
    Text(
        text = text,
        style = style.copy(fontFamily = FontFamily.Monospace),
        modifier = modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState()),
        maxLines = 1,
        softWrap = false,
    )
}

/** Material 3 surface card for list rows, clickable when [onClick] is non-null. */
@Composable
fun M3ListCard(
    onClick: (() -> Unit)?,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Surface(
        modifier = modifier
            .fillMaxWidth()
            .then(if (onClick != null) Modifier.clickable(onClick = onClick) else Modifier),
        shape = MaterialTheme.shapes.medium,
        color = MaterialTheme.colorScheme.surfaceContainerHigh,
        tonalElevation = 1.dp,
        content = content,
    )
}

/** Centered empty-state placeholder with an icon, [message] and optional [action]. */
@Composable
fun EmptyState(
    message: String,
    modifier: Modifier = Modifier,
    action: @Composable (() -> Unit)? = null,
) {
    Column(
        modifier = modifier
            .fillMaxWidth()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Surface(
            shape = MaterialTheme.shapes.large,
            color = MaterialTheme.colorScheme.surfaceContainer,
        ) {
            Icon(
                Icons.Outlined.Inbox,
                contentDescription = null,
                modifier = Modifier
                    .padding(24.dp)
                    .size(48.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Text(
            message,
            style = MaterialTheme.typography.bodyLarge,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.padding(top = 16.dp),
        )
        action?.let {
            Box(Modifier.padding(top = 16.dp)) { it() }
        }
    }
}

/** Formats an epoch-ms timestamp as a locale date, or `—` when unset. */
fun formatKeyDate(epochMs: Long): String =
    if (epochMs <= 0L) "—" else DateFormat.getDateInstance().format(Date(epochMs))

/** Formats a key id as an uppercase `0x…` hex string. */
fun formatKeyId(keyId: Long): String = "0x${keyId.toULong().toString(16).uppercase()}"

/** Builds a one-line summary of a key: user id, key id and secret/public kind. */
fun formatKeySummaryLine(key: KeySummary): String {
    val kind = if (key.isSecret) "secret" else "public"
    return "${key.primaryUserId ?: "Key"} · ${formatKeyId(key.masterKeyId)} · $kind"
}

/**
 * Small inline status/error message; renders nothing when [message] is blank.
 *
 * List/detail: full fingerprint lives on detail screen only.
 */
@Composable
fun StatusMessage(
    message: String,
    modifier: Modifier = Modifier,
    isError: Boolean = false,
) {
    if (message.isBlank()) return
    Text(
        text = message,
        modifier = modifier.padding(vertical = 4.dp),
        style = MaterialTheme.typography.bodySmall,
        color = if (isError) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.onSurfaceVariant,
    )
}

/** Abbreviates a fingerprint to `first4…last8`, collapsing whitespace. */
fun formatShortFingerprint(fingerprint: String): String {
    val compact = fingerprint.filter { !it.isWhitespace() }
    if (compact.length <= 12) return compact
    return "${compact.take(4)}…${compact.takeLast(8)}"
}
