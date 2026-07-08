package ltechnologies.onionphone.pgpshield.ui.theme

/**
 * The root Material 3 theme wrapper, including light/dark and dynamic color.
 */

import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.ExperimentalMaterial3ExpressiveApi
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.MotionScheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.dynamicDarkColorScheme
import androidx.compose.material3.dynamicLightColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext

private val DarkColorScheme = darkColorScheme(
    primary = PrimaryBlueDark,
    onPrimary = Color(0xFF001B3D),
    primaryContainer = Color(0xFF1A3A6B),
    onPrimaryContainer = Color(0xFFD6E4FF),
    secondary = SecondaryTeal,
    onSecondary = Color(0xFF00201C),
    secondaryContainer = Color(0xFF004D47),
    onSecondaryContainer = Color(0xFFB2DFDB),
    tertiary = TertiaryAmber,
    onTertiary = Color(0xFFFFE082),
    tertiaryContainer = Color(0xFF3D2C00),
    onTertiaryContainer = Color(0xFFFFE082),
    background = SurfaceDark,
    onBackground = Color(0xFFE3E2E8),
    surface = SurfaceDark,
    onSurface = Color(0xFFE3E2E8),
    onSurfaceVariant = Color(0xFFC4C6D0),
    surfaceContainerLowest = SurfaceContainerLowestDark,
    surfaceContainerLow = SurfaceContainerLowDark,
    surfaceContainer = SurfaceContainerDark,
    surfaceContainerHigh = SurfaceContainerHighDark,
    surfaceContainerHighest = SurfaceContainerHighestDark,
    outline = OutlineDark,
    outlineVariant = Color(0xFF44474F),
)

private val LightColorScheme = lightColorScheme(
    primary = PrimaryBlue,
    onPrimary = Color.White,
    primaryContainer = Color(0xFFD6E4FF),
    onPrimaryContainer = Color(0xFF001B3D),
    secondary = SecondaryTeal,
    onSecondary = Color.White,
    secondaryContainer = Color(0xFFB2DFDB),
    onSecondaryContainer = Color(0xFF00201C),
    tertiary = TertiaryAmber,
    onTertiary = Color.White,
    tertiaryContainer = Color(0xFFFFE082),
    onTertiaryContainer = Color(0xFF261900),
    background = SurfaceLight,
    onBackground = Color(0xFF1A1C22),
    surface = SurfaceLight,
    onSurface = Color(0xFF1A1C22),
    onSurfaceVariant = Color(0xFF44474F),
    surfaceContainerLowest = SurfaceContainerLowestLight,
    surfaceContainerLow = SurfaceContainerLowLight,
    surfaceContainer = SurfaceContainerLight,
    surfaceContainerHigh = SurfaceContainerHighLight,
    surfaceContainerHighest = SurfaceContainerHighestLight,
    outline = OutlineLight,
    outlineVariant = Color(0xFFC4C6D0),
)

/**
 * Applies the PGP Shield [MaterialTheme] (colors, typography, shapes, motion).
 *
 * @param darkTheme Whether to use the dark color scheme; defaults to the system.
 * @param dynamicColor Use Android 12+ dynamic (wallpaper) colors when available.
 * @param content The composable subtree to theme.
 */
@OptIn(ExperimentalMaterial3ExpressiveApi::class)
@Composable
fun PgpShieldTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit,
) {
    val context = LocalContext.current
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = PgpShieldTypography,
        shapes = PgpShieldShapes,
        motionScheme = MotionScheme.expressive(),
        content = content,
    )
}
