package ltechnologies.onionphone.pgpshield.data

import ltechnologies.onionphone.pgpshield.data.vault.KeyBlobStore
import java.util.concurrent.ConcurrentHashMap

/** ponytail: in-memory blob store for JVM unit tests (no Android Keystore). */
class InMemoryBlobStore : KeyBlobStore {
    private val blobs = ConcurrentHashMap<String, ByteArray>()

    override fun write(keyId: Long, data: ByteArray): String = store(keyId, "", data)

    override fun writePublic(keyId: Long, data: ByteArray): String = store(keyId, "_pub", data)

    override fun read(path: String): ByteArray =
        blobs[path]?.copyOf() ?: throw IllegalArgumentException("Missing blob $path")

    override fun delete(path: String) {
        blobs.remove(path)
    }

    private fun store(keyId: Long, suffix: String, data: ByteArray): String {
        val path = "mem://kr_$keyId$suffix"
        blobs[path] = data.copyOf()
        return path
    }
}
