package ltechnologies.onionphone.pgpshield.ui.theme

/**
 * Material 3 corner-radius shape tokens for the PGP Shield theme.
 */

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Shapes
import androidx.compose.ui.unit.dp

// ponytail: synced from docs/m3-tokens.xml corner radii
/** The app's [Shapes] set defining corner radii for Material components. */
val PgpShieldShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(12.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(28.dp),
    extraLarge = RoundedCornerShape(28.dp),
)
