package ltechnologies.onionphone.pgpshield.engine

/**
 * OpenPGP content signer that hashes locally and asks an OpenPGP Card for PSO:CDS.
 */

import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.security.MessageDigest
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DERNull
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x509.DigestInfo
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPPrivateKey
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.operator.PGPContentSigner
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder

/**
 * Builds a [PGPContentSigner] that never uses software private-key material —
 * the digest is completed on-device and signed via [SmartCardPort.sign].
 */
class SmartCardContentSignerBuilder(
    private val publicKey: PGPPublicKey,
    private val card: SmartCardPort,
    private val hashAlgorithm: Int = PgpAlgorithmPolicy.signatureHashForPublicKey(publicKey),
) : PGPContentSignerBuilder {
    @Throws(PGPException::class)
    override fun build(signatureType: Int, privateKey: PGPPrivateKey): PGPContentSigner {
        val keyId = privateKey.keyID
        val jcaDigest = when (hashAlgorithm) {
            HashAlgorithmTags.SHA256 -> "SHA-256"
            HashAlgorithmTags.SHA384 -> "SHA-384"
            HashAlgorithmTags.SHA512 -> "SHA-512"
            HashAlgorithmTags.SHA224 -> "SHA-224"
            else -> "SHA-256"
        }
        val digest = MessageDigest.getInstance(jcaDigest)
        val tee = ByteArrayOutputStream()
        return object : PGPContentSigner {
            override fun getOutputStream(): OutputStream = object : OutputStream() {
                override fun write(b: Int) {
                    digest.update(b.toByte())
                    tee.write(b)
                }

                override fun write(b: ByteArray, off: Int, len: Int) {
                    digest.update(b, off, len)
                    tee.write(b, off, len)
                }
            }

            override fun getSignature(): ByteArray {
                val hash = digest.digest()
                val payload = formatForCard(publicKey.algorithm, hashAlgorithm, hash)
                return try {
                    card.sign(payload, keyId)
                } catch (e: Exception) {
                    throw PGPException("Smart card sign failed: ${e.message}", e)
                }
            }

            override fun getDigest(): ByteArray = tee.toByteArray()

            override fun getType(): Int = signatureType

            override fun getHashAlgorithm(): Int = hashAlgorithm

            override fun getKeyAlgorithm(): Int = publicKey.algorithm

            override fun getKeyID(): Long = keyId
        }
    }

    companion object {
        /**
         * Formats a digest for OpenPGP Card PSO:CDS.
         * RSA expects DigestInfo; ECC/EdDSA typically take hash-alg-byte || digest.
         */
        fun formatForCard(keyAlgorithm: Int, hashAlgorithm: Int, hash: ByteArray): ByteArray =
            when (keyAlgorithm) {
                PublicKeyAlgorithmTags.RSA_GENERAL,
                PublicKeyAlgorithmTags.RSA_SIGN,
                -> DigestInfo(
                    AlgorithmIdentifier(oidForHash(hashAlgorithm), DERNull.INSTANCE),
                    hash,
                ).encoded
                else -> byteArrayOf(hashAlgorithm.toByte()) + hash
            }

        private fun oidForHash(hashAlgorithm: Int): ASN1ObjectIdentifier =
            when (hashAlgorithm) {
                HashAlgorithmTags.SHA256 -> NISTObjectIdentifiers.id_sha256
                HashAlgorithmTags.SHA384 -> NISTObjectIdentifiers.id_sha384
                HashAlgorithmTags.SHA512 -> NISTObjectIdentifiers.id_sha512
                HashAlgorithmTags.SHA224 -> NISTObjectIdentifiers.id_sha224
                else -> NISTObjectIdentifiers.id_sha256
            }
    }
}
