package ltechnologies.onionphone.pgpshield.data

/**
 * Persists S/MIME certificates and StrongBox/TEE-sealed private keys.
 */

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import java.io.File
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Base64
import javax.inject.Inject
import javax.inject.Singleton
import ltechnologies.onionphone.pgpshield.data.security.SensitiveMemory
import ltechnologies.onionphone.pgpshield.data.security.StrongBoxSealedBlobStore
import ltechnologies.onionphone.pgpshield.engine.SmimeEngine
import ltechnologies.onionphone.pgpshield.engine.SmimeIdentity
import timber.log.Timber

/** On-disk catalog of imported S/MIME identities. */
@Singleton
class SmimeCertificateStore @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val root = File(context.filesDir, "smime-certs").also { it.mkdirs() }
    private val engine = SmimeEngine()
    private val sealedKeys = StrongBoxSealedBlobStore(
        dir = root,
        keyAlias = SMIME_KEY_ALIAS,
        context = context,
        magic0 = 0x53, // S
        magic1 = 0x4D, // M
        magic2 = 0x4B, // K
    )

    /** Ensures the StrongBox/TEE wrapping key exists (warm path). */
    fun warmStrongBoxKey() {
        runCatching { sealedKeys.ensureKey() }
            .onFailure { Timber.w(it, "S/MIME StrongBox key warm-up deferred") }
    }

    fun listIdentities(): List<SmimeIdentity> =
        root.listFiles()?.filter { it.extension == "crt" }?.mapNotNull { crt ->
            runCatching {
                val alias = crt.nameWithoutExtension
                val cert = engine.importPemCertificate(crt.readBytes())
                val key = loadPrivateKey(alias)
                SmimeIdentity(alias = alias, certificate = cert, privateKey = key)
            }.getOrNull()
        }.orEmpty().sortedBy { it.alias }

    fun saveIdentity(alias: String, certificate: X509Certificate, privateKey: PrivateKey? = null) {
        val safe = sanitize(alias)
        File(root, "$safe.crt").writeText(toPem("CERTIFICATE", certificate.encoded))
        if (privateKey != null) {
            sealPrivateKey(safe, privateKey)
        }
    }

    fun deleteIdentity(alias: String) {
        val safe = sanitize(alias)
        File(root, "$safe.crt").delete()
        sealedKeys.delete(sealedName(safe))
        // Remove legacy plaintext PEM if present.
        wipeAndDelete(File(root, "$safe.key"))
    }

    fun importPkcs12(pkcs12: ByteArray, password: CharArray): List<SmimeIdentity> {
        val imported = engine.importPkcs12(pkcs12, password)
        for (id in imported) {
            saveIdentity(id.alias, id.certificate, id.privateKey)
        }
        return imported
    }

    private fun loadPrivateKey(alias: String): PrivateKey? {
        val sealed = sealedName(alias)
        if (sealedKeys.exists(sealed)) {
            val der = sealedKeys.unseal(sealed) ?: return null
            return try {
                engine.importPemPrivateKey(toPem("PRIVATE KEY", der).toByteArray(Charsets.UTF_8))
            } finally {
                SensitiveMemory.wipe(der)
            }
        }
        // Legacy plaintext PEM → migrate into StrongBox seal.
        val legacy = File(root, "$alias.key")
        if (!legacy.isFile) return null
        return runCatching {
            val pem = legacy.readBytes()
            val key = engine.importPemPrivateKey(pem)
            sealPrivateKey(alias, key)
            wipeAndDelete(legacy)
            Timber.i("Migrated S/MIME private key %s into StrongBox/TEE seal", alias)
            key
        }.getOrNull()
    }

    private fun sealPrivateKey(alias: String, privateKey: PrivateKey) {
        val der = privateKey.encoded
        try {
            sealedKeys.seal(sealedName(alias), der)
        } finally {
            SensitiveMemory.wipe(der)
        }
        wipeAndDelete(File(root, "$alias.key"))
    }

    private fun wipeAndDelete(file: File) {
        if (!file.isFile) return
        runCatching {
            val len = file.length().toInt().coerceAtMost(256 * 1024)
            if (len > 0) file.writeBytes(ByteArray(len))
        }
        file.delete()
    }

    private fun sanitize(alias: String): String =
        alias.replace(Regex("[^A-Za-z0-9._-]"), "_")

    private fun sealedName(alias: String): String = "$alias.key.sb"

    private fun toPem(type: String, der: ByteArray): String {
        val b64 = Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(der)
        return "-----BEGIN $type-----\n$b64\n-----END $type-----\n"
    }

    companion object {
        const val SMIME_KEY_ALIAS = "_pgp_shield_smime_v1_"
    }
}
