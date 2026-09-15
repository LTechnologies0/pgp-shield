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
    /** Legacy alias still used by some OpenKeychain-era clients. */
    const val ACTION_GET_SIGN_KEY_ID_LEGACY = "org.openintents.openpgp.action.GET_SIGN_KEY_ID_LEGACY"
    const val ACTION_GET_KEY_IDS = "org.openintents.openpgp.action.GET_KEY_IDS"
    const val ACTION_GET_KEY = "org.openintents.openpgp.action.GET_KEY"
    const val ACTION_BACKUP = "org.openintents.openpgp.action.BACKUP"
    const val ACTION_QUERY_AUTOCRYPT_STATUS = "org.openintents.openpgp.action.QUERY_AUTOCRYPT_STATUS"
    const val ACTION_UPDATE_AUTOCRYPT_PEER = "org.openintents.openpgp.action.UPDATE_AUTOCRYPT_PEER"
    /**
     * Autocrypt Setup Message export (openpgp-api literal action string, not the
     * `org.openintents.openpgp.action.*` prefix used by other actions).
     */
    const val ACTION_AUTOCRYPT_KEY_TRANSFER = "autocrypt_key_transfer"

    const val EXTRA_API_VERSION = "api_version"
    const val EXTRA_REQUEST_ASCII_ARMOR = "ascii_armor"
    // ENCRYPT / SIGN_AND_ENCRYPT: providers default this to true (OpenKeychain).
    // DETACHED_SIGN: openpgp-api defaults to false (binary signature).
    const val EXTRA_USER_IDS = "user_ids"
    const val EXTRA_KEY_IDS = "key_ids"
    /** Selected after USER_INTERACTION recipient picker (OpenPGP API). */
    const val EXTRA_KEY_IDS_SELECTED = "key_ids_selected"
    const val EXTRA_SIGN_KEY_ID = "sign_key_id"
    const val EXTRA_PASSPHRASE = "passphrase"
    const val EXTRA_ORIGINAL_FILENAME = "original_filename"
    const val EXTRA_ENABLE_COMPRESSION = "enable_compression"
    const val EXTRA_OPPORTUNISTIC_ENCRYPTION = "opportunistic"
    /** Optional ASCII-armor headers (ArrayList of "Name: value" lines). */
    const val EXTRA_CUSTOM_HEADERS = "custom_headers"
    const val EXTRA_KEY_ID = "key_id"
    const val EXTRA_BACKUP_SECRET = "backup_secret"
    const val EXTRA_DETACHED_SIGNATURE = "detached_signature"
    /** Preferred account / From: user id for GET_SIGN_KEY_ID (openpgp-api). */
    const val EXTRA_USER_ID = "user_id"
    /** Soft-preferred signing key id for GET_SIGN_KEY_ID picker / auto-select. */
    const val EXTRA_PRESELECT_KEY_ID = "preselect_key_id"
    /** When true, sign-key picker may show an Autocrypt setup hint (openpgp-api). */
    const val EXTRA_SHOW_AUTOCRYPT_HINT = "show_autocrypt_hint"
    /** Autocrypt / GET_KEY: strip other UIDs from exported public key. */
    const val EXTRA_MINIMIZE = "minimize"
    /** UID (or email) to keep when [EXTRA_MINIMIZE] is true. */
    const val EXTRA_MINIMIZE_USER_ID = "minimize_user_id"
    /** Mail From: address for signature sender-status matching. */
    const val EXTRA_SENDER_ADDRESS = "sender_address"
    /**
     * Client can handle insecure-crypto override UX (openpgp-api typo preserved:
     * `crpto` not `crypto`).
     */
    const val EXTRA_SUPPORT_OVERRIDE_CRYPTO_WARNING = "support_override_crpto_warning"
    /** Optional [android.os.Messenger] for decrypt progress (arg1=current, arg2=total). */
    const val EXTRA_PROGRESS_MESSENGER = "progress_messenger"
    const val EXTRA_DATA_LENGTH = "data_length"
    const val EXTRA_DECRYPTION_RESULT = "decryption_result"
    const val EXTRA_AUTOCRYPT_PEER_ID = "autocrypt_peer_id"
    const val EXTRA_AUTOCRYPT_PEER_UPDATE = "autocrypt_peer_update"
    const val EXTRA_AUTOCRYPT_PEER_GOSSIP_UPDATES = "autocrypt_peer_gossip_updates"

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
    const val RESULT_SIGNATURE_VERIFIED = "signature_verified"
    const val RESULT_KEYS_CONFIRMED = "keys_confirmed"
    const val RESULT_AUTOCRYPT_STATUS = "autocrypt_status"
    const val AUTOCRYPT_STATUS_UNAVAILABLE = 0
    const val AUTOCRYPT_STATUS_DISCOURAGE = 1
    const val AUTOCRYPT_STATUS_AVAILABLE = 2
    const val AUTOCRYPT_STATUS_MUTUAL = 3
    /** Primary user id of the selected signing key (GET_SIGN_KEY_ID). */
    const val RESULT_PRIMARY_USER_ID = "primary_user_id"
    /** Key creation time in ms since epoch (GET_SIGN_KEY_ID). */
    const val RESULT_KEY_CREATION_TIME = "key_creation_time"

    /** OpenKeychain / openpgp-api parcelable result extras (K-9, FairEmail). */
    const val RESULT_SIGNATURE = "signature"
    const val RESULT_DECRYPTION = "decryption"
    const val RESULT_METADATA = "metadata"
    /** Charset from ASCII-armor headers (openpgp-api). */
    const val RESULT_CHARSET = "charset"
    /**
     * PendingIntent explaining insecure crypto (weak algo / MDC issues).
     * Distinct from [RESULT_INTENT] (signer view / import).
     */
    const val RESULT_INSECURE_DETAIL_INTENT = "insecure_detail_intent"
    /**
     * Boolean: whether the insecure-crypto warning was already overridden for this
     * problem (OpenKeychain). Only set when [EXTRA_SUPPORT_OVERRIDE_CRYPTO_WARNING]
     * was true on the request.
     */
    const val RESULT_OVERRIDE_CRYPTO_WARNING = "override_crypto_warning"
}
