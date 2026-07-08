package ltechnologies.onionphone.pgpshield.openpgp

/**
 * String/int constants defining the OpenPGP API IPC contract.
 */

/**
 * Mirrors org.openintents.openpgp.util.OpenPgpApi constants for OpenKeychain-compatible IPC.
 *
 * Groups the service intent name, API version, action strings, request/result
 * extra keys and result codes exchanged with OpenPGP API clients.
 */
object OpenPgpConstants {
    const val SERVICE_INTENT_2 = "org.openintents.openpgp.IOpenPgpService2"
    const val API_VERSION = 11

    const val ACTION_CHECK_PERMISSION = "org.openintents.openpgp.action.CHECK_PERMISSION"
    const val ACTION_SIGN = "org.openintents.openpgp.action.SIGN"
    const val ACTION_CLEARTEXT_SIGN = "org.openintents.openpgp.action.CLEARTEXT_SIGN"
    const val ACTION_DETACHED_SIGN = "org.openintents.openpgp.action.DETACHED_SIGN"
    const val ACTION_ENCRYPT = "org.openintents.openpgp.action.ENCRYPT"
    const val ACTION_SIGN_AND_ENCRYPT = "org.openintents.openpgp.action.SIGN_AND_ENCRYPT"
    const val ACTION_DECRYPT_VERIFY = "org.openintents.openpgp.action.DECRYPT_VERIFY"
    const val ACTION_DECRYPT_METADATA = "org.openintents.openpgp.action.DECRYPT_METADATA"
    const val ACTION_GET_SIGN_KEY_ID = "org.openintents.openpgp.action.GET_SIGN_KEY_ID"
    const val ACTION_GET_KEY_IDS = "org.openintents.openpgp.action.GET_KEY_IDS"
    const val ACTION_GET_KEY = "org.openintents.openpgp.action.GET_KEY"
    const val ACTION_BACKUP = "org.openintents.openpgp.action.BACKUP"

    const val EXTRA_API_VERSION = "api_version"
    const val EXTRA_REQUEST_ASCII_ARMOR = "ascii_armor"
    const val EXTRA_USER_IDS = "user_ids"
    const val EXTRA_KEY_IDS = "key_ids"
    const val EXTRA_SIGN_KEY_ID = "sign_key_id"
    const val EXTRA_PASSPHRASE = "passphrase"
    const val EXTRA_ORIGINAL_FILENAME = "original_filename"
    const val EXTRA_ENABLE_COMPRESSION = "enable_compression"
    const val EXTRA_KEY_ID = "key_id"
    const val EXTRA_BACKUP_SECRET = "backup_secret"
    const val EXTRA_DETACHED_SIGNATURE = "detached_signature"

    const val RESULT_CODE = "result_code"
    const val RESULT_CODE_ERROR = 0
    const val RESULT_CODE_SUCCESS = 1
    const val RESULT_CODE_USER_INTERACTION_REQUIRED = 2

    const val RESULT_ERROR = "error"
    const val RESULT_INTENT = "intent"
    const val RESULT_KEY_IDS = "key_ids"
    const val RESULT_DETACHED_SIGNATURE = "detached_signature"
    const val RESULT_SIGNATURE_MICALG = "signature_micalg"
    const val RESULT_SIGN_KEY_ID = "sign_key_id"
}
