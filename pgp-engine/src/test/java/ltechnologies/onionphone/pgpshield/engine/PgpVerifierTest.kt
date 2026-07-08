package ltechnologies.onionphone.pgpshield.engine

import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class PgpVerifierTest {
    @Test
    fun cleartextSignRoundTrip_verify() {
        BouncyCastleProviderHolder.ensureRegistered()
        val passphrase = "verify-test-pass".toCharArray()
        val generated = KeyGenerator().generateKeyRing(
            GenerateKeyRequest(userId = "Verify <v@e.com>", passphrase = passphrase),
        )
        val message = "Signed line\n"
        val signed = PgpSigner().sign(
            SignRequest(message.toByteArray(), generated.secretArmored, passphrase),
        )
        val result = PgpVerifier().verify(
            VerifyRequest(
                signedOrDetached = signed.output,
                publicKeyRingsArmored = listOf(generated.publicArmored),
            ),
        )
        assertTrue(result.valid, result.error)
        assertTrue(String(result.message!!, Charsets.UTF_8).contains("Signed line"))
    }
}
