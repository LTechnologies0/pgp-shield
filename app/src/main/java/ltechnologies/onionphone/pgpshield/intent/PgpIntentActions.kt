package ltechnologies.onionphone.pgpshield.intent

/**
 * Intent action strings and extras for PGP Shield's Intent-based entry points.
 */

/**
 * Constants for the app's own encrypt/decrypt/import intents plus compatibility
 * aliases for OpenKeychain (`org.sufficientlysecure.keychain`) actions.
 */
object PgpIntentActions {
    const val ENCRYPT_TEXT = "ltechnologies.onionphone.pgpshield.action.ENCRYPT_TEXT"
    const val DECRYPT_TEXT = "ltechnologies.onionphone.pgpshield.action.DECRYPT_TEXT"
    const val ENCRYPT_DATA = "ltechnologies.onionphone.pgpshield.action.ENCRYPT_DATA"
    const val DECRYPT_DATA = "ltechnologies.onionphone.pgpshield.action.DECRYPT_DATA"
    const val ENCRYPT_FOLDER = "ltechnologies.onionphone.pgpshield.action.ENCRYPT_FOLDER"
    const val EXTRA_TEXT = "ltechnologies.onionphone.pgpshield.extra.TEXT"
    const val EXTRA_RELATIVE_PATHS = "ltechnologies.onionphone.pgpshield.extra.RELATIVE_PATHS"
    const val EXTRA_OUTPUT_PATH = "ltechnologies.onionphone.pgpshield.extra.OUTPUT_PATH"
    const val EXTRA_ARCHIVE_NAME = "ltechnologies.onionphone.pgpshield.extra.ARCHIVE_NAME"
    const val EXTRA_FOLDER_LABEL = "ltechnologies.onionphone.pgpshield.extra.FOLDER_LABEL"
    /** Absolute paths of source files (Secure-File-Manager integration). */
    const val EXTRA_SOURCE_PATHS = "ltechnologies.onionphone.pgpshield.extra.SOURCE_PATHS"
    /** When true, delete plaintext after writing ciphertext (SFM setting). */
    const val EXTRA_DELETE_SOURCE = "ltechnologies.onionphone.pgpshield.extra.DELETE_SOURCE"

    // OpenKeychain / org.sufficientlysecure.keychain action aliases
    const val OKC_ENCRYPT_TEXT = "org.sufficientlysecure.keychain.action.ENCRYPT_TEXT"
    const val OKC_DECRYPT_TEXT = "org.sufficientlysecure.keychain.action.DECRYPT_TEXT"
    const val OKC_ENCRYPT_DATA = "org.sufficientlysecure.keychain.action.ENCRYPT_DATA"
    const val OKC_DECRYPT_DATA = "org.sufficientlysecure.keychain.action.DECRYPT_DATA"
    const val OKC_IMPORT_KEY = "org.sufficientlysecure.keychain.action.IMPORT_KEY"
    const val OKC_IMPORT_KEY_FROM_KEYSERVER = "org.sufficientlysecure.keychain.action.IMPORT_KEY_FROM_KEYSERVER"
    const val OKC_IMPORT_KEY_FROM_QR_CODE = "org.sufficientlysecure.keychain.action.IMPORT_KEY_FROM_QR_CODE"
}
