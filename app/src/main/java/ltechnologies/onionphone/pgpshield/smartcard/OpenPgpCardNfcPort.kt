package ltechnologies.onionphone.pgpshield.smartcard

/**
 * NFC IsoDep implementation of [SmartCardPort] for OpenPGP Cards / YubiKey NFC.
 */

import android.nfc.Tag
import android.nfc.tech.IsoDep
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton
import ltechnologies.onionphone.pgpshield.engine.OpenPgpCardInfo
import ltechnologies.onionphone.pgpshield.engine.PgpException
import ltechnologies.onionphone.pgpshield.engine.SmartCardPort

@Singleton
class OpenPgpCardNfcPort @Inject constructor() : SmartCardPort {
    private val isoDep = AtomicReference<IsoDep?>(null)
    private val session = AtomicReference<OpenPgpCardSession?>(null)
    private val boundKeyIds = AtomicReference<Set<Long>>(emptySet())

    /** Attach an NFC [Tag] discovered by the activity (Reader Mode / intent). */
    fun attachTag(tag: Tag): OpenPgpCardInfo {
        val dep = IsoDep.get(tag) ?: throw PgpException("Tag does not support IsoDep")
        dep.timeout = 15_000
        dep.connect()
        isoDep.set(dep)
        val sess = OpenPgpCardSession(
            channel = ApduChannel { cmd ->
                dep.transceive(cmd)
            },
            transport = "NFC",
        )
        val info = sess.select()
        session.set(sess)
        return info
    }

    override fun bindKeyIds(ids: Set<Long>) {
        boundKeyIds.set(ids)
    }

    override fun isAvailable(): Boolean =
        isoDep.get()?.isConnected == true && session.get() != null

    override fun cardInfo(): OpenPgpCardInfo? = session.get()?.info

    override fun verifyPin(pin: CharArray): Boolean {
        val sess = session.get() ?: return false
        return runCatching {
            sess.verifyPin(pin)
            true
        }.getOrDefault(false)
    }

    override fun sign(data: ByteArray, keyId: Long): ByteArray {
        val sess = session.get() ?: throw PgpException("No NFC OpenPGP card session")
        return sess.sign(data)
    }

    override fun decrypt(sessionKey: ByteArray, keyId: Long): ByteArray {
        val sess = session.get() ?: throw PgpException("No NFC OpenPGP card session")
        return sess.decrypt(sessionKey)
    }

    override fun ownsKey(keyId: Long): Boolean =
        keyId in boundKeyIds.get() && isAvailable()

    override fun close() {
        session.set(null)
        runCatching { isoDep.getAndSet(null)?.close() }
    }
}
