package ltechnologies.onionphone.pgpshield.provider

/**
 * OpenKeychain-compatible content provider exposing per-email key status.
 *
 * Lets external apps look up whether keys exist for given email addresses,
 * matching the historical `email_status` provider contract.
 */

import android.content.ContentProvider
import android.content.ContentValues
import android.content.UriMatcher
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.provider.BaseColumns
import dagger.hilt.android.EntryPointAccessors
import ltechnologies.onionphone.pgpshield.PgpShieldApplication
import ltechnologies.onionphone.pgpshield.data.db.UserIdDao
import ltechnologies.onionphone.pgpshield.di.ProviderEntryPoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking

/**
 * OpenKeychain-compatible exported key query provider (email_status).
 * ponytail: verification status not tracked yet — all keys reported as unverified.
 */
class ExportedKeyProvider : ContentProvider() {
    private lateinit var userIdDao: UserIdDao
    private val matcher = UriMatcher(UriMatcher.NO_MATCH).apply {
        addURI(AUTHORITY, PATH_EMAIL_STATUS, MATCH_EMAIL_STATUS)
        addURI(AUTHORITY, "$PATH_EMAIL_STATUS/*", MATCH_EMAIL_STATUS)
    }

    /** Resolves the [UserIdDao] from the Hilt graph via an entry point. */
    override fun onCreate(): Boolean {
        val app = context?.applicationContext as? PgpShieldApplication ?: return false
        val entryPoint = EntryPointAccessors.fromApplication(app, ProviderEntryPoint::class.java)
        userIdDao = entryPoint.userIdDao()
        return true
    }

    /**
     * Returns a cursor of key status rows for the email addresses supplied in
     * [selectionArgs]; only the `email_status` URI is supported.
     */
    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? {
        if (matcher.match(uri) != MATCH_EMAIL_STATUS) return null
        val emails = selectionArgs?.toList().orEmpty()
        val rows = runBlocking(Dispatchers.IO) {
            if (emails.isEmpty()) {
                emptyList()
            } else {
                emails.flatMap { email ->
                    userIdDao.findByUserIdFragment(email).map { entity ->
                        Row(
                            emailAddress = email,
                            userId = entity.userId,
                            status = KEY_STATUS_UNVERIFIED,
                            masterKeyId = entity.masterKeyId,
                        )
                    }
                }
            }
        }
        val columns = projection ?: DEFAULT_PROJECTION
        val cursor = MatrixCursor(columns)
        for (row in rows) {
            val values = Array(columns.size) { index ->
                when (columns[index]) {
                    BaseColumns._ID -> row.masterKeyId
                    COLUMN_EMAIL_ADDRESS -> row.emailAddress
                    COLUMN_USER_ID -> row.userId
                    COLUMN_EMAIL_STATUS -> row.status
                    COLUMN_MASTER_KEY_ID -> row.masterKeyId
                    else -> null
                }
            }
            cursor.addRow(values)
        }
        return cursor
    }

    /** Returns the MIME type for the `email_status` directory URI. */
    override fun getType(uri: Uri): String? =
        if (matcher.match(uri) == MATCH_EMAIL_STATUS) {
            "vnd.android.cursor.dir/vnd.$AUTHORITY.email_status"
        } else {
            null
        }

    /** Unsupported: this provider is read-only and rejects inserts. */
    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    /** Unsupported: this provider is read-only and performs no deletes. */
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    /** Unsupported: this provider is read-only and performs no updates. */
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = 0

    private data class Row(
        val emailAddress: String,
        val userId: String,
        val status: Int,
        val masterKeyId: Long,
    )

    /** Authority, paths, column names, status codes and the content URI. */
    companion object {
        const val AUTHORITY = "ltechnologies.onionphone.pgpshield.provider.exported"
        const val PATH_EMAIL_STATUS = "email_status"

        const val KEY_STATUS_UNVERIFIED = 1
        const val KEY_STATUS_VERIFIED = 2

        const val COLUMN_EMAIL_ADDRESS = "email_address"
        const val COLUMN_USER_ID = "user_id"
        const val COLUMN_EMAIL_STATUS = "email_status"
        const val COLUMN_MASTER_KEY_ID = "master_key_id"

        val CONTENT_URI: Uri = Uri.parse("content://$AUTHORITY/$PATH_EMAIL_STATUS")

        private val DEFAULT_PROJECTION = arrayOf(
            BaseColumns._ID,
            COLUMN_EMAIL_ADDRESS,
            COLUMN_USER_ID,
            COLUMN_EMAIL_STATUS,
            COLUMN_MASTER_KEY_ID,
        )

        private const val MATCH_EMAIL_STATUS = 1
    }
}
