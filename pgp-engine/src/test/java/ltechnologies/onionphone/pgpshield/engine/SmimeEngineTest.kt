package ltechnologies.onionphone.pgpshield.engine

import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.cert.X509Certificate
import java.util.Date
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/** CMS / S/MIME round-trip coverage. */
class SmimeEngineTest {
    @Test
    fun envelopedData_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val (cert, key) = selfSignedRsa("CN=SmimeTest")
        val engine = SmimeEngine()
        val plain = "hello smime cms".toByteArray()
        val enc = engine.encrypt(plain, listOf(cert))
        val dec = engine.decrypt(enc, key)
        assertArrayEquals(plain, dec)
    }

    @Test
    fun signedData_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val (cert, key) = selfSignedRsa("CN=SmimeSigner")
        val engine = SmimeEngine()
        val plain = "signed cms body".toByteArray()
        val signed = engine.sign(plain, key, cert)
        val result = engine.verify(signed, listOf(cert))
        assertTrue(result.valid)
        assertTrue(result.signatureValid)
        assertArrayEquals(plain, result.content)
    }

    @Test
    fun signedData_emptyTrustAnchors_notValid() {
        BouncyCastleProviderHolder.ensureRegistered()
        val (cert, key) = selfSignedRsa("CN=SmimeUntrusted")
        val engine = SmimeEngine()
        val plain = "signed without anchors".toByteArray()
        val signed = engine.sign(plain, key, cert)
        val result = engine.verify(signed, emptyList())
        assertTrue(result.signatureValid)
        assertTrue(!result.valid)
    }

    private fun selfSignedRsa(dn: String): Pair<X509Certificate, java.security.PrivateKey> {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val kp = kpg.generateKeyPair()
        val now = System.currentTimeMillis()
        val notBefore = Date(now - 60_000)
        val notAfter = Date(now + 365L * 24 * 60 * 60 * 1000)
        val builder = JcaX509v3CertificateBuilder(
            X500Name(dn),
            BigInteger.valueOf(now),
            notBefore,
            notAfter,
            X500Name(dn),
            kp.public,
        )
        val signer = JcaContentSignerBuilder("SHA256withRSA")
            .setProvider(BouncyCastleProviderHolder.PROVIDER)
            .build(kp.private)
        val cert = JcaX509CertificateConverter()
            .setProvider(BouncyCastleProviderHolder.PROVIDER)
            .getCertificate(builder.build(signer))
        return cert to kp.private
    }
}
