package ltechnologies.onionphone.pgpshield.data.security

import android.content.Context
import android.util.Base64
import dagger.hilt.android.qualifiers.ApplicationContext
import timber.log.Timber
import java.io.File
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Snapshot of the passphrase-wrapping Keystore key after creation/inspection.
 *
 * @property alias AndroidKeyStore alias.
 * @property strongBoxBacked `true` when security level is StrongBox (API 31+).
 * @property insideSecureHardware `true` when the key lives in TEE/StrongBox (not soft KS).
 * @property userAuthenticationRequired Always `true` for this vault.
 */
data class PassphraseWrappingKeyInfo(
    val alias: String,
    val strongBoxBacked: Boolean?,
    val insideSecureHardware: Boolean,
    val userAuthenticationRequired: Boolean,
)

/**
 * Auth-bound AES-GCM vault for OpenPGP passphrases.
 *
 * Android Keystore / StrongBox cannot execute OpenPGP private-key ops for Bouncy Castle.
 * Instead we:
 * 1. Generate a high-entropy passphrase
 * 2. Wrap OpenPGP secret packets with that passphrase (existing S2K path)
 * 3. Encrypt the passphrase under an auth-bound Keystore AES key (StrongBox preferred)
 * 4. Require BIOMETRIC_STRONG | DEVICE_CREDENTIAL via [Cipher] + BiometricPrompt CryptoObject
 * 5. Wipe passphrase buffers after each use
 *
 * Soft (non-hardware) Keystore keys are rejected — passphrase wrapping must stay in the enclave.
 */
@Singleton
class HardwarePassphraseVault @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val random = SecureRandom()
    private val storeDir: File
        get() = File(context.filesDir, DIR_NAME).also { it.mkdirs() }

    /** Whether device lock + hardware Keystore can back passphrase wrapping. */
    fun isAvailable(): Boolean {
        val keyguard = context.getSystemService(android.app.KeyguardManager::class.java)
        if (keyguard?.isDeviceSecure != true) return false
        return try {
            val info = ensureWrappingKey()
            info.insideSecureHardware
        } catch (e: Exception) {
            Timber.w(e, "Hardware passphrase vault unavailable")
            false
        }
    }

    /** Creates (or loads) the wrapping key; fails if not inside secure hardware. */
    fun ensureWrappingKey(): PassphraseWrappingKeyInfo {
        val handle = StrongBoxAesKeyFactory.getOrCreate(
            context = context,
            alias = ALIAS,
            userAuthenticationRequired = true,
            requireInsideSecureHardware = true,
        )
        return PassphraseWrappingKeyInfo(
            alias = handle.alias,
            strongBoxBacked = handle.strongBoxBacked,
            insideSecureHardware = handle.insideSecureHardware,
            userAuthenticationRequired = handle.userAuthenticationRequired,
        )
    }

    /** Inspects the wrapping key without creating it. */
    fun inspectWrappingKey(): PassphraseWrappingKeyInfo? {
        val handle = StrongBoxAesKeyFactory.inspect(ALIAS) ?: return null
        return PassphraseWrappingKeyInfo(
            alias = handle.alias,
            strongBoxBacked = handle.strongBoxBacked,
            insideSecureHardware = handle.insideSecureHardware,
            userAuthenticationRequired = handle.userAuthenticationRequired,
        )
    }

    /** High-entropy OpenPGP passphrase (32 random bytes, URL-safe Base64). */
    fun generatePassphrase(): CharArray {
        val raw = ByteArray(PASSPHRASE_BYTES)
        random.nextBytes(raw)
        return try {
            Base64.encodeToString(raw, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
                .toCharArray()
        } finally {
            SensitiveMemory.wipe(raw)
        }
    }

    /**
     * Prepares an encrypt [Cipher] for sealing a new passphrase.
     * Must be authenticated via BiometricPrompt CryptoObject before [sealPassphrase].
     */
    fun prepareEncryptCipher(): Cipher {
        ensureWrappingKey()
        val key = requireKey()
        return Cipher.getInstance(TRANSFORMATION).also {
            it.init(Cipher.ENCRYPT_MODE, key)
        }
    }

    /**
     * Prepares a decrypt [Cipher] for [keyId]'s sealed passphrase.
     * Must be authenticated via BiometricPrompt CryptoObject before [unlockPassphrase].
     */
    fun prepareDecryptCipher(keyId: Long): Cipher {
        ensureWrappingKey()
        val blob = readBlob(keyId) ?: error("No hardware-managed passphrase for key")
        val key = requireKey()
        val iv = blob.copyOfRange(HEADER_LEN, HEADER_LEN + IV_LEN)
        return try {
            Cipher.getInstance(TRANSFORMATION).also {
                it.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
            }
        } finally {
            SensitiveMemory.wipe(iv)
        }
    }

    /** Seals [passphrase] for [keyId] using an already-authenticated encrypt [cipher]. */
    fun sealPassphrase(keyId: Long, passphrase: CharArray, cipher: Cipher) {
        require(cipher.iv != null && cipher.iv.size == IV_LEN) { "Invalid encrypt cipher IV" }
        val utf8 = CharArrayEncoder.encodeUtf8(passphrase)
        try {
            val ciphertext = cipher.doFinal(utf8)
            val out = ByteArray(HEADER_LEN + IV_LEN + ciphertext.size)
            out[0] = MAGIC_0
            out[1] = MAGIC_1
            out[2] = MAGIC_2
            out[3] = VERSION
            System.arraycopy(cipher.iv, 0, out, HEADER_LEN, IV_LEN)
            System.arraycopy(ciphertext, 0, out, HEADER_LEN + IV_LEN, ciphertext.size)
            fileFor(keyId).writeBytes(out)
            SensitiveMemory.wipe(out, ciphertext)
        } finally {
            SensitiveMemory.wipe(utf8)
        }
    }

    /** Unlocks the passphrase for [keyId] using an already-authenticated decrypt [cipher]. */
    fun unlockPassphrase(keyId: Long, cipher: Cipher): CharArray {
        val blob = readBlob(keyId) ?: error("No hardware-managed passphrase for key")
        val ciphertext = blob.copyOfRange(HEADER_LEN + IV_LEN, blob.size)
        return try {
            val plain = cipher.doFinal(ciphertext)
            try {
                CharArrayEncoder.decodeUtf8(plain)
            } finally {
                SensitiveMemory.wipe(plain)
            }
        } finally {
            SensitiveMemory.wipe(blob, ciphertext)
        }
    }

    fun hasPassphrase(keyId: Long): Boolean = fileFor(keyId).isFile

    fun deletePassphrase(keyId: Long) {
        val f = fileFor(keyId)
        if (f.isFile) {
            runCatching {
                val len = f.length().toInt().coerceAtMost(64 * 1024)
                if (len > 0) f.writeBytes(ByteArray(len))
            }
            f.delete()
        }
    }

    private fun requireKey(): SecretKey =
        StrongBoxAesKeyFactory.inspect(ALIAS)?.key
            ?: error("Wrapping key missing")

    private fun readBlob(keyId: Long): ByteArray? {
        val f = fileFor(keyId)
        if (!f.isFile) return null
        val bytes = f.readBytes()
        require(bytes.size > HEADER_LEN + IV_LEN) { "Corrupt passphrase blob" }
        require(
            bytes[0] == MAGIC_0 && bytes[1] == MAGIC_1 &&
                bytes[2] == MAGIC_2 && bytes[3] == VERSION,
        ) { "Invalid passphrase blob magic" }
        return bytes
    }

    private fun fileFor(keyId: Long): File =
        File(storeDir, "%016x.bin".format(keyId))

    companion object {
        const val ALIAS = "_pgp_shield_hw_passphrase_v1_"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val DIR_NAME = "hw_passphrases"
        private const val PASSPHRASE_BYTES = 32
        private const val IV_LEN = 12
        private const val GCM_TAG_BITS = 128
        private const val HEADER_LEN = 4
        private const val MAGIC_0: Byte = 0x50 // P
        private const val MAGIC_1: Byte = 0x48 // H
        private const val MAGIC_2: Byte = 0x50 // P
        private const val VERSION: Byte = 1
    }
}

/** UTF-8 encode/decode without intermediate [String] for wipeable secrets. */
internal object CharArrayEncoder {
    fun encodeUtf8(chars: CharArray): ByteArray {
        val cb = java.nio.CharBuffer.wrap(chars)
        val bb = Charsets.UTF_8.encode(cb)
        val out = ByteArray(bb.remaining())
        bb.get(out)
        return out
    }

    fun decodeUtf8(bytes: ByteArray): CharArray {
        val bb = java.nio.ByteBuffer.wrap(bytes)
        val cb = Charsets.UTF_8.decode(bb)
        val out = CharArray(cb.remaining())
        cb.get(out)
        return out
    }
}
