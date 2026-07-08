package ltechnologies.onionphone.pgpshield.ui.components

/**
 * Responsive layout primitives that adapt content to window size and orientation.
 *
 * Provides breakpoint classification, derived spacing/width metrics, and helper
 * composables for centered content, two-pane layouts and adaptive text fields.
 */

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.Stable
import androidx.compose.runtime.remember
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp

/**
 * Window width buckets used to select layout behavior.
 *
 * ponytail: Configuration-based breakpoints; upgrade path = material3-window-size-class for foldables.
 */
enum class WindowLayout { Compact, Medium, Expanded, Tv }

/** Immutable set of layout metrics derived from the current window size. */
@Stable
data class AdaptiveMetrics(
    val layout: WindowLayout,
    val isLandscape: Boolean,
    val contentMaxWidth: Dp,
    val horizontalPadding: Dp,
    val sectionSpacing: Dp,
    val useTwoPane: Boolean,
    val useCompactButtons: Boolean,
    val listMinCellWidth: Dp,
)

/** When > 0, [rememberAdaptiveMetrics] uses this instead of full screen width (nav rail, etc.). */
val LocalContentWidthDp = staticCompositionLocalOf { 0 }

private const val COMPACT_MAX = 600
private const val MEDIUM_MAX = 840
private const val EXPANDED_MAX = 1200
private const val TWO_PANE_MIN_WIDTH = 900
private const val MIN_PANE_WIDTH = 380

/** Computes [AdaptiveMetrics] from raw window [widthDp] and [heightDp]. */
fun computeAdaptiveMetrics(widthDp: Int, heightDp: Int): AdaptiveMetrics {
    val landscape = widthDp > heightDp
    val layout = when {
        widthDp < COMPACT_MAX -> WindowLayout.Compact
        widthDp < MEDIUM_MAX -> WindowLayout.Medium
        widthDp < EXPANDED_MAX -> WindowLayout.Expanded
        else -> WindowLayout.Tv
    }
    val paneWidth = if (landscape && widthDp >= TWO_PANE_MIN_WIDTH) {
        (widthDp - 16) / 2
    } else {
        widthDp
    }
    val useTwoPane = layout != WindowLayout.Compact &&
        landscape &&
        widthDp >= TWO_PANE_MIN_WIDTH &&
        paneWidth >= MIN_PANE_WIDTH
    val contentMax = when (layout) {
        WindowLayout.Compact -> Dp.Unspecified
        WindowLayout.Medium -> 720.dp
        WindowLayout.Expanded -> 960.dp
        WindowLayout.Tv -> 1280.dp
    }
    return AdaptiveMetrics(
        layout = layout,
        isLandscape = landscape,
        contentMaxWidth = contentMax,
        horizontalPadding = when (layout) {
            WindowLayout.Compact -> 16.dp
            WindowLayout.Medium -> 24.dp
            WindowLayout.Expanded -> 32.dp
            WindowLayout.Tv -> 48.dp
        },
        sectionSpacing = when (layout) {
            WindowLayout.Compact -> 8.dp
            WindowLayout.Medium -> 12.dp
            WindowLayout.Expanded -> 16.dp
            WindowLayout.Tv -> 20.dp
        },
        useTwoPane = useTwoPane,
        useCompactButtons = !useTwoPane || paneWidth < 520,
        listMinCellWidth = when (layout) {
            WindowLayout.Compact -> Dp.Unspecified
            WindowLayout.Medium -> 280.dp
            WindowLayout.Expanded -> 320.dp
            WindowLayout.Tv -> 360.dp
        },
    )
}

/**
 * Remembers [AdaptiveMetrics] for the current configuration, preferring
 * [availableWidthDp] then the measured content width then the screen width.
 */
@Composable
fun rememberAdaptiveMetrics(availableWidthDp: Int? = null): AdaptiveMetrics {
    val cfg = LocalConfiguration.current
    val measuredWidth = LocalContentWidthDp.current
    val width = availableWidthDp
        ?: measuredWidth.takeIf { it > 0 }
        ?: cfg.screenWidthDp
    val height = cfg.screenHeightDp
    return remember(width, height) { computeAdaptiveMetrics(width, height) }
}

/** Measures the width actually available to content (inside nav rail, padding, etc.). */
@Composable
fun ProvideAdaptiveMetrics(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    BoxWithConstraints(modifier.fillMaxSize()) {
        val widthDp = maxWidth.value.toInt().coerceAtLeast(1)
        CompositionLocalProvider(LocalContentWidthDp provides widthDp) {
            content()
        }
    }
}

/** Centers [content] and caps its width to [AdaptiveMetrics.contentMaxWidth]. */
@Composable
fun AdaptiveContentWidth(
    modifier: Modifier = Modifier,
    metrics: AdaptiveMetrics = rememberAdaptiveMetrics(),
    content: @Composable () -> Unit,
) {
    Box(
        modifier = modifier.fillMaxWidth(),
        contentAlignment = Alignment.TopCenter,
    ) {
        Box(
            modifier = Modifier
                .then(
                    if (metrics.contentMaxWidth != Dp.Unspecified) {
                        Modifier.widthIn(max = metrics.contentMaxWidth)
                    } else {
                        Modifier
                    },
                )
                .fillMaxWidth()
                .padding(horizontal = metrics.horizontalPadding),
        ) {
            content()
        }
    }
}

/**
 * A vertically arranged, optionally scrollable screen column with adaptive
 * padding and width constraints.
 */
@Composable
fun AdaptiveScreenColumn(
    modifier: Modifier = Modifier,
    scroll: Boolean = true,
    verticalArrangement: Arrangement.Vertical = Arrangement.Top,
    metrics: AdaptiveMetrics = rememberAdaptiveMetrics(),
    /** Detail screens (key detail, etc.) need full width — not capped at 960dp. */
    constrainMaxWidth: Boolean = true,
    content: @Composable ColumnScope.() -> Unit,
) {
    val scrollMod = if (scroll) Modifier.verticalScroll(rememberScrollState()) else Modifier
    val column = @Composable {
        Column(
            modifier = modifier
                .fillMaxWidth()
                .then(scrollMod)
                .padding(bottom = metrics.sectionSpacing * 2),
            verticalArrangement = verticalArrangement,
            content = content,
        )
    }
    if (constrainMaxWidth) {
        AdaptiveContentWidth(metrics = metrics) { column() }
    } else {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = metrics.horizontalPadding),
        ) {
            column()
        }
    }
}

/** Side-by-side on wide landscape; stacked otherwise. */
@Composable
fun AdaptiveTwoPane(
    modifier: Modifier = Modifier,
    metrics: AdaptiveMetrics = rememberAdaptiveMetrics(),
    spacing: Dp = 16.dp,
    startWeight: Float = 1f,
    endWeight: Float = 1f,
    start: @Composable () -> Unit,
    end: @Composable () -> Unit,
) {
    if (metrics.useTwoPane) {
        Row(
            modifier = modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(spacing),
        ) {
            Box(Modifier.weight(startWeight).fillMaxWidth()) { start() }
            Box(Modifier.weight(endWeight).fillMaxWidth()) { end() }
        }
    } else {
        Column(
            modifier = modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(spacing),
        ) {
            start()
            end()
        }
    }
}

/** Applies a minimum text-field height appropriate for the current [metrics]. */
fun Modifier.adaptiveTextFieldHeight(
    minLines: Int = 4,
    metrics: AdaptiveMetrics,
): Modifier {
    val minHeight = when {
        metrics.useTwoPane -> 120.dp
        metrics.isLandscape && metrics.layout == WindowLayout.Compact -> 80.dp
        metrics.layout == WindowLayout.Tv -> (minLines * 28).dp
        else -> (minLines * 24).dp
    }
    return heightIn(min = minHeight)
}
