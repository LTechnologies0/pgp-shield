package ltechnologies.onionphone.pgpshield.engine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class EmailAddressTest {
    @Test
    fun normalize_extractsAngleAddress() {
        assertEquals("alice@example.org", EmailAddress.normalize("Alice <alice@example.org>"))
        assertEquals("alice@example.org", EmailAddress.normalize("alice@example.org"))
    }

    @Test
    fun normalize_rejectsWildcardsAndBlank() {
        assertNull(EmailAddress.normalize(""))
        assertNull(EmailAddress.normalize("%@example.org"))
        assertNull(EmailAddress.normalize("*@example.org"))
        assertEquals("user_name@example.org", EmailAddress.normalize("user_name@example.org"))
        assertNull(EmailAddress.normalize("not-an-email"))
    }

    @Test
    fun userIdMatchesEmail_isExactNotSubstring() {
        assertTrue(EmailAddress.userIdMatchesEmail("Alice <alice@example.org>", "alice@example.org"))
        assertFalse(EmailAddress.userIdMatchesEmail("Alice <alice@example.org>", "ice@example.org"))
        assertFalse(EmailAddress.userIdMatchesEmail("Alice <mallice@example.org>", "alice@example.org"))
        assertFalse(EmailAddress.userIdMatchesEmail("Alice <alice@example.org>", "%@example.org"))
    }
}
