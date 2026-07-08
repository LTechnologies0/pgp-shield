package ltechnologies.onionphone.pgpshield.intent

import org.junit.Assert.assertEquals
import org.junit.Test

class IntentResultWriterTest {
    @Test
    fun gpgOutputName_appendsExtension() {
        assertEquals("notes.txt.gpg", IntentResultWriter.gpgOutputName("notes.txt"))
        assertEquals("archive.gpg", IntentResultWriter.gpgOutputName("archive"))
    }

    @Test
    fun decryptedOutputName_stripsKnownSuffixes() {
        assertEquals("notes.txt", IntentResultWriter.decryptedOutputName("notes.txt.gpg"))
        assertEquals("notes.txt", IntentResultWriter.decryptedOutputName("notes.txt.PGP"))
        assertEquals("message", IntentResultWriter.decryptedOutputName("message.asc"))
        assertEquals("binary", IntentResultWriter.decryptedOutputName("binary"))
    }
}
