package ltechnologies.onionphone.pgpshield.engine

import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream

class MalformedPgpTest {
    @Test
    fun garbageInputThrows() {
        BouncyCastleProviderHolder.ensureRegistered()
        assertThrows(PgpException::class.java) {
            KeyRingReader().readPublicKeyRing(ByteArrayInputStream("not pgp".toByteArray()))
        }
    }
}
