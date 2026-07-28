package ltechnologies.onionphone.pgpshield.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.Timeout
import java.util.concurrent.TimeUnit

@Timeout(120, unit = TimeUnit.SECONDS)
class PgpAuthenticatorTest {
    @Test
    fun authenticate_and_verify_roundTrip() {
        BouncyCastleProviderHolder.ensureRegistered()
        val generated = KeyGenerator().generateKeyRing(
            GenerateKeyRequest(
                userId = "Auth Tester <auth@example.org>",
                passphrase = "test-pass".toCharArray(),
                algorithmType = KeyAlgorithmType.RSA,
                rsaBits = 2048,
            ),
        )
        val challenge = "login-nonce-${System.currentTimeMillis()}".toByteArray(Charsets.UTF_8)
        val auth = PgpAuthenticator().authenticate(
            AuthenticateRequest(
                challenge = challenge,
                secretKeyRingArmored = generated.secretArmored,
                passphrase = "test-pass".toCharArray(),
            ),
        )
        assertTrue(auth.signatureArmored.isNotEmpty())
        val verified = PgpAuthenticator().verify(
            VerifyAuthenticationRequest(
                challenge = challenge,
                signatureArmored = auth.signatureArmored,
                publicKeyRingArmored = generated.publicArmored,
            ),
        )
        assertTrue(verified.valid)
        assertEquals(auth.keyId, verified.signerKeyId)
    }

    @Test
    fun verify_failsOnTamperedChallenge() {
        BouncyCastleProviderHolder.ensureRegistered()
        val generated = KeyGenerator().generateKeyRing(
            GenerateKeyRequest(
                userId = "Auth Tester <auth2@example.org>",
                passphrase = "test-pass".toCharArray(),
                algorithmType = KeyAlgorithmType.RSA,
                rsaBits = 2048,
            ),
        )
        val auth = PgpAuthenticator().authenticate(
            AuthenticateRequest(
                challenge = "original".toByteArray(),
                secretKeyRingArmored = generated.secretArmored,
                passphrase = "test-pass".toCharArray(),
            ),
        )
        val verified = PgpAuthenticator().verify(
            VerifyAuthenticationRequest(
                challenge = "tampered".toByteArray(),
                signatureArmored = auth.signatureArmored,
                publicKeyRingArmored = generated.publicArmored,
            ),
        )
        assertFalse(verified.valid)
    }
}
