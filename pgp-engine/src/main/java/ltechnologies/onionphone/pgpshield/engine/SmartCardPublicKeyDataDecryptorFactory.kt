package ltechnologies.onionphone.pgpshield.engine

/**
 * PublicKeyDataDecryptorFactory that recovers the session key via an OpenPGP Card.
 */

import org.bouncycastle.bcpg.AEADEncDataPacket
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket
import org.bouncycastle.openpgp.PGPException
import org.bouncycastle.openpgp.PGPSessionKey
import org.bouncycastle.openpgp.operator.AbstractPublicKeyDataDecryptorFactory
import org.bouncycastle.openpgp.operator.PGPDataDecryptor
import org.bouncycastle.openpgp.operator.bc.BcSessionKeyDataDecryptorFactory

/**
 * Recovers PKESK session material by sending cipher bytes to [SmartCardPort.decrypt].
 *
 * The card must already have an authenticated PIN session. Symmetric payload decrypt
 * is delegated to [BcSessionKeyDataDecryptorFactory].
 */
class SmartCardPublicKeyDataDecryptorFactory(
    private val card: SmartCardPort,
    private val keyId: Long,
) : AbstractPublicKeyDataDecryptorFactory() {
    override fun recoverSessionData(keyAlgorithm: Int, secKeyData: Array<ByteArray>, pkeskVersion: Int): ByteArray {
        val combined = if (secKeyData.size == 1) {
            secKeyData[0]
        } else {
            val total = secKeyData.sumOf { it.size }
            val out = ByteArray(total)
            var off = 0
            for (part in secKeyData) {
                System.arraycopy(part, 0, out, off, part.size)
                off += part.size
            }
            out
        }
        return try {
            card.decrypt(combined, keyId)
        } catch (e: Exception) {
            throw PGPException("Smart card session-key decrypt failed: ${e.message}", e)
        }
    }

    override fun createDataDecryptor(
        withIntegrityPacket: Boolean,
        encAlgorithm: Int,
        key: ByteArray,
    ): PGPDataDecryptor {
        val sessionKey = PGPSessionKey(encAlgorithm, key)
        return BcSessionKeyDataDecryptorFactory(sessionKey)
            .createDataDecryptor(withIntegrityPacket, encAlgorithm, key)
    }

    override fun createDataDecryptor(
        aeadEncDataPacket: AEADEncDataPacket,
        sessionKey: PGPSessionKey,
    ): PGPDataDecryptor =
        BcSessionKeyDataDecryptorFactory(sessionKey).createDataDecryptor(aeadEncDataPacket, sessionKey)

    override fun createDataDecryptor(
        seipd: SymmetricEncIntegrityPacket,
        sessionKey: PGPSessionKey,
    ): PGPDataDecryptor =
        BcSessionKeyDataDecryptorFactory(sessionKey).createDataDecryptor(seipd, sessionKey)
}
