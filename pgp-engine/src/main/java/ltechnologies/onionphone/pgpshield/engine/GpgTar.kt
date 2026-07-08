package ltechnologies.onionphone.pgpshield.engine

/**
 * Multi-file archive encryption using a custom container inside OpenPGP literal data.
 *
 * Packs named files into a `PST1` binary archive, encrypts the blob as a single
 * OpenPGP message, and unpacks after decryption.
 */

import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/** A named file entry in a [GpgTar] archive. */
data class NamedFile(
    val name: String,
    val data: ByteArray,
)

/** Encrypt request: multiple files to one OpenPGP ciphertext. */
data class GpgTarEncryptRequest(
    val files: List<NamedFile>,
    val recipientKeyRings: List<ByteArray>,
    val asciiArmor: Boolean = true,
)

/** Decrypt request for a [GpgTar]-encrypted archive. */
data class GpgTarDecryptRequest(
    val ciphertext: ByteArray,
    val secretKeyRingArmored: ByteArray,
    val passphrase: CharArray,
)

/** Encrypts and decrypts multi-file archives wrapped in OpenPGP messages. */
class GpgTar {
    private val encryptor = PgpEncryptor()
    private val decryptor = PgpDecryptor()

    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /**
     * Packs [request.files] and encrypts to OpenPGP recipients.
     *
     * @throws IllegalArgumentException if the file list is empty.
     */
    fun encrypt(request: GpgTarEncryptRequest): EncryptResult {
        require(request.files.isNotEmpty()) { "At least one file required" }
        val payload = pack(request.files)
        return encryptor.encrypt(
            EncryptRequest(
                plaintext = payload,
                recipientKeyRings = request.recipientKeyRings,
                asciiArmor = request.asciiArmor,
                fileName = TAR_LITERAL_NAME,
            ),
        )
    }

    /** Decrypts a [GpgTar] ciphertext and unpacks contained files. */
    fun decrypt(request: GpgTarDecryptRequest): List<NamedFile> {
        val result = decryptor.decrypt(
            DecryptRequest(
                ciphertext = request.ciphertext,
                secretKeyRingArmored = request.secretKeyRingArmored,
                passphrase = request.passphrase,
            ),
        )
        return unpack(result.plaintext)
    }

    companion object {
        /** Literal data packet filename used for the packed archive inside OpenPGP. */
        const val TAR_LITERAL_NAME = "pgpshield.tar"
        private val MAGIC = byteArrayOf('P'.code.toByte(), 'S'.code.toByte(), 'T'.code.toByte(), 1)
        private const val MAX_NAME_LEN = 255
        // ponytail: cap total archive size; upgrade path is streaming tar if needed
        private val MAX_ARCHIVE_BYTES = PgpIo.MAX_STREAM_BYTES

        /**
         * Serializes [files] into the `PST1` binary archive format.
         *
         * @throws PgpException if total size exceeds [PgpIo.MAX_STREAM_BYTES].
         */
        fun pack(files: List<NamedFile>): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(MAGIC)
            var total = MAGIC.size.toLong()
            for (file in files) {
                val nameBytes = file.name.toByteArray(StandardCharsets.UTF_8)
                require(nameBytes.size in 1..MAX_NAME_LEN) { "File name length out of range: ${file.name}" }
                total += 2 + nameBytes.size + 4 + file.data.size
                if (total > MAX_ARCHIVE_BYTES) {
                    throw PgpException("Archive exceeds maximum allowed size ($MAX_ARCHIVE_BYTES bytes)")
                }
                out.write(nameBytes.size shr 8)
                out.write(nameBytes.size)
                out.write(nameBytes)
                val lenBuf = ByteBuffer.allocate(4).putInt(file.data.size).array()
                out.write(lenBuf)
                out.write(file.data)
            }
            return out.toByteArray()
        }

        /**
         * Deserializes a `PST1` archive produced by [pack].
         *
         * @throws IllegalArgumentException on invalid magic, truncation, or empty archive.
         */
        fun unpack(payload: ByteArray): List<NamedFile> {
            require(payload.size >= MAGIC.size) { "Archive too short" }
            require(payload.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) { "Invalid archive magic" }
            val files = ArrayList<NamedFile>()
            var offset = MAGIC.size
            while (offset < payload.size) {
                require(offset + 2 <= payload.size) { "Truncated archive header" }
                val nameLen = ((payload[offset].toInt() and 0xFF) shl 8) or (payload[offset + 1].toInt() and 0xFF)
                offset += 2
                require(nameLen in 1..MAX_NAME_LEN) { "Invalid name length" }
                require(offset + nameLen + 4 <= payload.size) { "Truncated file name" }
                val name = String(payload, offset, nameLen, StandardCharsets.UTF_8)
                offset += nameLen
                val dataLen = ByteBuffer.wrap(payload, offset, 4).int
                offset += 4
                require(dataLen >= 0) { "Negative file size" }
                require(offset + dataLen <= payload.size) { "Truncated file data" }
                val data = payload.copyOfRange(offset, offset + dataLen)
                offset += dataLen
                files.add(NamedFile(name, data))
            }
            require(files.isNotEmpty()) { "Empty archive" }
            return files
        }
    }
}
