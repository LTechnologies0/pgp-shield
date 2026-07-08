package ltechnologies.onionphone.pgpshield.data.vault

/**
 * Abstraction for persisting armored PGP key ring blobs outside the Room database.
 *
 * Implementations are responsible for encryption at rest, path naming, and secure deletion.
 * The database stores metadata and blob paths; actual key material lives in the blob store.
 */
interface KeyBlobStore {
    /**
     * Persists secret key ring bytes for [keyId].
     *
     * @return Absolute path to the stored blob for recording in the database.
     */
    fun write(keyId: Long, data: ByteArray): String

    /**
     * Persists public key ring bytes for [keyId], typically alongside a secret blob.
     *
     * @return Absolute path to the stored public blob.
     */
    fun writePublic(keyId: Long, data: ByteArray): String

    /**
     * Loads and decrypts key ring bytes from [path].
     */
    fun read(path: String): ByteArray

    /**
     * Removes the blob at [path], including any secure-wipe steps the implementation supports.
     */
    fun delete(path: String)
}
