package ltechnologies.onionphone.pgpshield.ui.components

/**
 * A tab container that keeps its content composed while hidden to preserve state.
 */

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.layout
import androidx.compose.ui.zIndex

/**
 * Keep tab composed after first visit; hidden tabs skip layout/draw.
 * @param fillMaxSize true for main nav slots; false when stacked in scroll content.
 */
@Composable
fun RetainedTab(
    visible: Boolean,
    modifier: Modifier = Modifier,
    fillMaxSize: Boolean = true,
    content: @Composable () -> Unit,
) {
    var retained by rememberSaveable { mutableStateOf(visible) }
    if (visible) retained = true
    if (!retained) return
    Box(
        modifier = modifier
            .zIndex(if (visible) 1f else 0f)
            .then(if (fillMaxSize) Modifier.fillMaxSize() else Modifier)
            .layout { measurable, constraints ->
                if (!visible) {
                    layout(0, 0) {}
                } else {
                    val placeable = measurable.measure(constraints)
                    layout(placeable.width, placeable.height) { placeable.place(0, 0) }
                }
            }
            .graphicsLayer { alpha = if (visible) 1f else 0f },
    ) {
        content()
    }
}
