package ltechnologies.onionphone.pgpshield.data.db

import androidx.room.Entity
import androidx.room.ForeignKey
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * Room entity definitions for PGP Shield local persistence.
 *
 * Tables cover key ring metadata, user ids, third-party API grants, overlay per-app
 * configuration, and padding templates for steganographic encoding.
 */

/**
 * Metadata row for a stored OpenPGP key ring; armored bytes live in [KeyBlobStore].
 *
 * @property masterKeyId Primary key; 64-bit OpenPGP master key id.
 * @property fingerprint Display fingerprint with optional spacing.
 * @property isSecret Whether the blob at [blobPath] contains secret key material.
 * @property isRevoked Local revoked flag (may also be set in the key itself).
 * @property blobPath Absolute path to secret or public armored blob.
 * @property publicBlobPath Optional path to extracted public blob when [isSecret] is true.
 * @property createdAt Import or generation time (epoch millis).
 * @property primaryAlgorithm Human-readable label for the primary key algorithm.
 * @property subkeyCount Number of subkeys when last parsed.
 * @property trustLevel Local trust: 0=unknown, 1=marginal, 2=full, 3=never.
 */
@Entity(tableName = "key_rings")
data class KeyRingEntity(
    @PrimaryKey val masterKeyId: Long,
    val fingerprint: String,
    val isSecret: Boolean,
    val isRevoked: Boolean,
    val blobPath: String,
    val publicBlobPath: String? = null,
    val createdAt: Long,
    val primaryAlgorithm: String = "RSA 3072",
    val subkeyCount: Int = 1,
    /** 0=unknown, 1=marginal, 2=full, 3=never */
    val trustLevel: Int = 0,
)

/**
 * User id (uid) packet associated with a key ring.
 *
 * @property id Surrogate primary key.
 * @property masterKeyId Foreign key to [KeyRingEntity.masterKeyId].
 * @property userId Full uid string (e.g. `Name <email@example.com>`).
 * @property isPrimary Whether this uid is the primary uid on the key.
 */
@Entity(
    tableName = "user_ids",
    foreignKeys = [
        ForeignKey(
            entity = KeyRingEntity::class,
            parentColumns = ["masterKeyId"],
            childColumns = ["masterKeyId"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index("masterKeyId")],
)
data class UserIdEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val masterKeyId: Long,
    val userId: String,
    val isPrimary: Boolean,
)

/**
 * Third-party app granted permission to call the PGP Shield IPC API.
 *
 * @property packageName Android package name (primary key).
 * @property grantedAt Epoch millis when access was granted.
 */
@Entity(
    tableName = "api_apps",
    primaryKeys = ["packageName"],
)
data class ApiAppEntity(
    val packageName: String,
    val grantedAt: Long,
)

/**
 * Key id explicitly allowed for a granted API client app.
 *
 * @property id Surrogate primary key.
 * @property packageName Owning app package (foreign key to [ApiAppEntity]).
 * @property keyId Master key id the app may use for crypto operations.
 */
@Entity(
    tableName = "api_allowed_keys",
    foreignKeys = [
        ForeignKey(
            entity = ApiAppEntity::class,
            parentColumns = ["packageName"],
            childColumns = ["packageName"],
            onDelete = ForeignKey.CASCADE,
        ),
    ],
    indices = [Index("packageName")],
)
data class ApiAllowedKeyEntity(
    @PrimaryKey(autoGenerate = true) val id: Long = 0,
    val packageName: String,
    val keyId: Long,
)

/**
 * Per-app overlay encryption settings for messaging apps.
 *
 * @property packageName Target app package name (primary key).
 * @property encodingMethod [EncodingRegistry] id for the steganographic method.
 * @property recipientKeyIds Comma-separated encrypt recipient key ids.
 * @property decryptKeyId Key id used when decrypting overlay payloads.
 * @property encryptKeyId Optional override encrypt key id.
 * @property paddingTemplateId Template id when using padding encoding.
 * @property enabled Whether overlay is active for this app.
 * @property overlayTextSizeSp Floating overlay text size in sp.
 * @property overlayAlpha Overlay window alpha (0–1).
 * @property minDecoyChars Minimum visible decoy character count for zero-width encoding.
 * @property composeViaClipboard Whether compose flow uses clipboard injection.
 * @property autoMode Automation level: `manual`, `suggest`, or `auto_send`.
 * @property showResultToast Whether to show a toast after overlay crypto.
 * @property requireConfirmBeforeSetText Whether user must confirm before replacing field text.
 */
@Entity(
    tableName = "overlay_app_config",
    primaryKeys = ["packageName"],
)
data class OverlayAppConfigEntity(
    val packageName: String,
    val encodingMethod: String,
    val recipientKeyIds: String,
    val decryptKeyId: Long?,
    val encryptKeyId: Long? = null,
    val paddingTemplateId: String? = null,
    val enabled: Boolean,
    val overlayTextSizeSp: Float = 14f,
    val overlayAlpha: Float = 0.95f,
    val minDecoyChars: Int = 20,
    val composeViaClipboard: Boolean = false,
    /** manual|suggest|auto_send */
    val autoMode: String = "manual",
    val showResultToast: Boolean = true,
    val requireConfirmBeforeSetText: Boolean = false,
)

/**
 * Reusable cover text template for [PaddingEncoder].
 *
 * @property templateId Stable template identifier (primary key).
 * @property title Title line inserted before the hidden payload.
 * @property content Body text surrounding the payload marker.
 */
@Entity(tableName = "padding_templates")
data class PaddingTemplateEntity(
    @PrimaryKey val templateId: String,
    val title: String,
    val content: String,
)
