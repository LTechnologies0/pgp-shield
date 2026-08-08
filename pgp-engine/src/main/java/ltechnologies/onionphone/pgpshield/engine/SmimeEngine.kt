package ltechnologies.onionphone.pgpshield.engine

/**
 * S/MIME (CMS) encrypt / decrypt / sign / verify via Bouncy Castle PKIX.
 */

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.cert.jcajce.JcaCertStore
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cms.CMSAlgorithm
import org.bouncycastle.cms.CMSEnvelopedData
import org.bouncycastle.cms.CMSEnvelopedDataGenerator
import org.bouncycastle.cms.CMSException
import org.bouncycastle.cms.CMSProcessableByteArray
import org.bouncycastle.cms.CMSSignedData
import org.bouncycastle.cms.CMSSignedDataGenerator
import org.bouncycastle.cms.CMSTypedData
import org.bouncycastle.cms.RecipientInformation
import org.bouncycastle.cms.SignerInformation
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder

/** In-memory X.509 identity used for S/MIME operations. */
data class SmimeIdentity(
    val alias: String,
    val certificate: X509Certificate,
    val privateKey: PrivateKey? = null,
)

/** Result of verifying a CMS signed message. */
data class SmimeVerifyResult(
    val content: ByteArray,
    /**
     * True only when the CMS signature verifies **and** the signer chains to a provided
     * trust anchor. Empty [trustAnchors] never yields `valid=true` (fail closed).
     */
    val valid: Boolean,
    val signerSubjectDn: String?,
    /** Cryptographic signature check succeeded (independent of trust anchors). */
    val signatureValid: Boolean = false,
)

/**
 * CMS / S/MIME engine backed by Bouncy Castle `bcpkix`.
 *
 * Supports PKCS#12 import, PEM cert import, enveloped-data encrypt/decrypt,
 * and detached/attached CMS signatures.
 */
class SmimeEngine {
    init {
        BouncyCastleProviderHolder.ensureRegistered()
    }

    /** Encrypts [plaintext] to one or more recipient certificates (KeyTransRecipient). */
    fun encrypt(plaintext: ByteArray, recipientCerts: List<X509Certificate>): ByteArray {
        require(recipientCerts.isNotEmpty()) { "At least one recipient certificate required" }
        try {
            val gen = CMSEnvelopedDataGenerator()
            for (cert in recipientCerts) {
                gen.addRecipientInfoGenerator(JceKeyTransRecipientInfoGenerator(cert).setProvider(BouncyCastleProviderHolder.PROVIDER))
            }
            val encryptor = JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC)
                .setProvider(BouncyCastleProviderHolder.PROVIDER)
                .build()
            val enveloped = gen.generate(CMSProcessableByteArray(plaintext), encryptor)
            return enveloped.encoded
        } catch (e: CMSException) {
            throw PgpException("S/MIME encrypt failed: ${e.message}", cause = e)
        } catch (e: Exception) {
            throw PgpException("S/MIME encrypt failed: ${e.message}", cause = e)
        }
    }

    /** Decrypts CMS EnvelopedData using [privateKey]. */
    fun decrypt(ciphertext: ByteArray, privateKey: PrivateKey): ByteArray {
        try {
            val enveloped = CMSEnvelopedData(ciphertext)
            val recipients = enveloped.recipientInfos.recipients
            val iter = recipients.iterator()
            while (iter.hasNext()) {
                val recipient = iter.next() as RecipientInformation
                val data = recipient.getContent(
                    JceKeyTransEnvelopedRecipient(privateKey).setProvider(BouncyCastleProviderHolder.PROVIDER),
                )
                return data
            }
            throw PgpException("S/MIME decrypt: no matching recipient")
        } catch (e: PgpException) {
            throw e
        } catch (e: Exception) {
            throw PgpException("S/MIME decrypt failed: ${e.message}", cause = e)
        }
    }

    /** Creates a CMS SignedData (attached content) over [content]. */
    fun sign(content: ByteArray, privateKey: PrivateKey, certificate: X509Certificate): ByteArray {
        try {
            val gen = CMSSignedDataGenerator()
            val contentSigner = JcaContentSignerBuilder(signatureAlgFor(privateKey))
                .setProvider(BouncyCastleProviderHolder.PROVIDER)
                .build(privateKey)
            val digestProvider = JcaDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProviderHolder.PROVIDER)
                .build()
            gen.addSignerInfoGenerator(
                JcaSignerInfoGeneratorBuilder(digestProvider).build(contentSigner, certificate),
            )
            gen.addCertificates(JcaCertStore(listOf(certificate)))
            val msg: CMSTypedData = CMSProcessableByteArray(content)
            return gen.generate(msg, true).encoded
        } catch (e: Exception) {
            throw PgpException("S/MIME sign failed: ${e.message}", cause = e)
        }
    }

    /** Verifies CMS SignedData; returns content and validity of the first signer. */
    fun verify(signedCms: ByteArray, trustAnchors: List<X509Certificate> = emptyList()): SmimeVerifyResult {
        try {
            val signed = CMSSignedData(signedCms)
            val content = ByteArrayOutputStream().use { out ->
                signed.signedContent?.write(out)
                out.toByteArray()
            }
            val converter = JcaX509CertificateConverter().setProvider(BouncyCastleProviderHolder.PROVIDER)
            @Suppress("UNCHECKED_CAST")
            val holders = (signed.certificates.getMatches(null) as Collection<*>)
                .filterIsInstance<org.bouncycastle.cert.X509CertificateHolder>()
            val certs = holders.map { converter.getCertificate(it) }
            var signatureValid = false
            var trusted = false
            var subject: String? = null
            for (raw in signed.signerInfos.signers) {
                val si = raw as SignerInformation
                for (cert in certs) {
                    val verifier = JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(BouncyCastleProviderHolder.PROVIDER)
                        .build(cert)
                    if (si.verify(verifier)) {
                        subject = cert.subjectX500Principal.name
                        signatureValid = true
                        // Fail closed: require at least one trust anchor match.
                        trusted = trustAnchors.isNotEmpty() &&
                            trustAnchors.any { anchorsMatch(cert, it) }
                        break
                    }
                }
                if (signatureValid) break
            }
            return SmimeVerifyResult(
                content = content,
                valid = signatureValid && trusted,
                signerSubjectDn = subject,
                signatureValid = signatureValid,
            )
        } catch (e: Exception) {
            throw PgpException("S/MIME verify failed: ${e.message}", cause = e)
        }
    }

    /** Loads identities from a PKCS#12 blob. */
    fun importPkcs12(pkcs12: ByteArray, password: CharArray, aliasPrefix: String = "smime"): List<SmimeIdentity> {
        val ks = KeyStore.getInstance("PKCS12")
        ks.load(ByteArrayInputStream(pkcs12), password)
        val out = ArrayList<SmimeIdentity>()
        val aliases = ks.aliases()
        while (aliases.hasMoreElements()) {
            val alias = aliases.nextElement()
            val cert = ks.getCertificate(alias) as? X509Certificate ?: continue
            val key = runCatching { ks.getKey(alias, password) as? PrivateKey }.getOrNull()
            out.add(SmimeIdentity(alias = alias.ifBlank { "$aliasPrefix-${out.size}" }, certificate = cert, privateKey = key))
        }
        if (out.isEmpty()) throw PgpException("PKCS#12 contained no X.509 certificates")
        return out
    }

    /** Parses a PEM-encoded X.509 certificate. */
    fun importPemCertificate(pem: ByteArray): X509Certificate {
        val cf = CertificateFactory.getInstance("X.509")
        return cf.generateCertificate(ByteArrayInputStream(pem)) as X509Certificate
    }

    /** Parses PEM private key (unencrypted PKCS#8 or traditional). */
    fun importPemPrivateKey(pem: ByteArray): PrivateKey {
        PEMParser(pem.inputStream().reader()).use { parser ->
            val obj = parser.readObject()
                ?: throw PgpException("Empty PEM private key")
            val converter = JcaPEMKeyConverter().setProvider(BouncyCastleProviderHolder.PROVIDER)
            return when (obj) {
                is PEMKeyPair -> converter.getKeyPair(obj).private
                is PrivateKeyInfo -> converter.getPrivateKey(obj)
                else -> throw PgpException("Unsupported PEM object: ${obj.javaClass.simpleName}")
            }
        }
    }

    /** True when [cert] is currently within its validity window. */
    fun isCertCurrentlyValid(cert: X509Certificate, at: Date = Date()): Boolean =
        runCatching {
            cert.checkValidity(at)
            true
        }.getOrDefault(false)

    private fun anchorsMatch(cert: X509Certificate, anchor: X509Certificate): Boolean =
        cert == anchor || cert.issuerX500Principal == anchor.subjectX500Principal

    private fun signatureAlgFor(key: PrivateKey): String =
        when (key.algorithm.uppercase()) {
            "RSA" -> "SHA256withRSA"
            "EC", "ECDSA" -> "SHA256withECDSA"
            "DSA" -> "SHA256withDSA"
            "ED25519" -> "Ed25519"
            else -> "SHA256withRSA"
        }
}
