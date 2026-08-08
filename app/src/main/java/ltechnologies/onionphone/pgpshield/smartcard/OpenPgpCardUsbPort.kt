package ltechnologies.onionphone.pgpshield.smartcard

/**
 * USB CCID host transport for OpenPGP Cards (YubiKey OTG).
 *
 * Implements a minimal CCID bulk XfrBlock path. Phones without USB host / OTG
 * report unavailable.
 */

import android.content.Context
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import dagger.hilt.android.qualifiers.ApplicationContext
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.inject.Inject
import javax.inject.Singleton
import ltechnologies.onionphone.pgpshield.engine.OpenPgpCardInfo
import ltechnologies.onionphone.pgpshield.engine.PgpException
import ltechnologies.onionphone.pgpshield.engine.SmartCardPort

@Singleton
class OpenPgpCardUsbPort @Inject constructor(
    @ApplicationContext private val context: Context,
) : SmartCardPort {
    private val manager = context.getSystemService(UsbManager::class.java)
    private val connectionRef = AtomicReference<android.hardware.usb.UsbDeviceConnection?>(null)
    private val bulkOut = AtomicReference<UsbEndpoint?>(null)
    private val bulkIn = AtomicReference<UsbEndpoint?>(null)
    private val session = AtomicReference<OpenPgpCardSession?>(null)
    private val seq = AtomicInteger(0)
    private val boundKeyIds = AtomicReference<Set<Long>>(emptySet())

    fun attachDevice(device: UsbDevice): OpenPgpCardInfo {
        val iface = findCcidInterface(device) ?: throw PgpException("No CCID interface on USB device")
        val conn = manager.openDevice(device) ?: throw PgpException("USB permission denied")
        if (!conn.claimInterface(iface, true)) {
            conn.close()
            throw PgpException("Failed to claim CCID interface")
        }
        var outEp: UsbEndpoint? = null
        var inEp: UsbEndpoint? = null
        for (i in 0 until iface.endpointCount) {
            val ep = iface.getEndpoint(i)
            if (ep.type != UsbConstants.USB_ENDPOINT_XFER_BULK) continue
            if (ep.direction == UsbConstants.USB_DIR_OUT) outEp = ep
            if (ep.direction == UsbConstants.USB_DIR_IN) inEp = ep
        }
        if (outEp == null || inEp == null) {
            conn.releaseInterface(iface)
            conn.close()
            throw PgpException("CCID bulk endpoints missing")
        }
        connectionRef.set(conn)
        bulkOut.set(outEp)
        bulkIn.set(inEp)
        val sess = OpenPgpCardSession(
            channel = ApduChannel { cmd -> transceiveCcid(cmd) },
            transport = "USB",
        )
        val info = sess.select()
        session.set(sess)
        return info
    }

    override fun bindKeyIds(ids: Set<Long>) {
        boundKeyIds.set(ids)
    }

    /** Request USB host permission for [device]; call [onGranted] when the user allows. */
    fun requestPermission(device: UsbDevice, onGranted: (UsbDevice) -> Unit, onDenied: () -> Unit) {
        val usb = manager
        if (usb == null) {
            onDenied()
            return
        }
        if (usb.hasPermission(device)) {
            onGranted(device)
            return
        }
        val action = ACTION_USB_PERMISSION
        val filter = android.content.IntentFilter(action)
        var finished = false
        val receiver = object : android.content.BroadcastReceiver() {
            override fun onReceive(context: android.content.Context, intent: android.content.Intent) {
                if (intent.action != action || finished) return
                finished = true
                runCatching { context.unregisterReceiver(this) }
                val granted = intent.getBooleanExtra(UsbManager.EXTRA_PERMISSION_GRANTED, false)
                val dev = intent.getParcelableExtraCompatible(UsbManager.EXTRA_DEVICE)
                if (granted && dev != null) onGranted(dev) else onDenied()
            }
        }
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            context.registerReceiver(receiver, filter, android.content.Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(receiver, filter)
        }
        val pi = android.app.PendingIntent.getBroadcast(
            context,
            0,
            android.content.Intent(action).setPackage(context.packageName),
            android.app.PendingIntent.FLAG_UPDATE_CURRENT or android.app.PendingIntent.FLAG_MUTABLE,
        )
        try {
            usb.requestPermission(device, pi)
        } catch (e: Exception) {
            finished = true
            runCatching { context.unregisterReceiver(receiver) }
            onDenied()
        }
    }

    @Suppress("DEPRECATION")
    private fun android.content.Intent.getParcelableExtraCompatible(key: String): UsbDevice? =
        if (android.os.Build.VERSION.SDK_INT >= 33) {
            getParcelableExtra(key, UsbDevice::class.java)
        } else {
            getParcelableExtra(key)
        }

    companion object {
        private const val ACTION_USB_PERMISSION = "ltechnologies.onionphone.pgpshield.USB_PERMISSION"
    }

    fun listCandidateDevices(): List<UsbDevice> =
        manager?.deviceList?.values?.filter { findCcidInterface(it) != null }.orEmpty()

    override fun isAvailable(): Boolean =
        connectionRef.get() != null && session.get() != null

    override fun cardInfo(): OpenPgpCardInfo? = session.get()?.info

    override fun verifyPin(pin: CharArray): Boolean {
        val sess = session.get() ?: return false
        return runCatching {
            sess.verifyPin(pin)
            true
        }.getOrDefault(false)
    }

    override fun sign(data: ByteArray, keyId: Long): ByteArray {
        val sess = session.get() ?: throw PgpException("No USB OpenPGP card session")
        return sess.sign(data)
    }

    override fun decrypt(sessionKey: ByteArray, keyId: Long): ByteArray {
        val sess = session.get() ?: throw PgpException("No USB OpenPGP card session")
        return sess.decrypt(sessionKey)
    }

    override fun ownsKey(keyId: Long): Boolean =
        keyId in boundKeyIds.get() && isAvailable()

    override fun close() {
        session.set(null)
        runCatching { connectionRef.getAndSet(null)?.close() }
        bulkOut.set(null)
        bulkIn.set(null)
    }

    private fun findCcidInterface(device: UsbDevice): UsbInterface? {
        for (i in 0 until device.interfaceCount) {
            val iface = device.getInterface(i)
            // CCID class 0x0B or vendor-specific smartcard interfaces
            if (iface.interfaceClass == 0x0B || iface.interfaceClass == 0xFF) {
                return iface
            }
        }
        return null
    }

    private fun transceiveCcid(apdu: ByteArray): ByteArray {
        val conn = connectionRef.get() ?: throw PgpException("USB not connected")
        val out = bulkOut.get() ?: throw PgpException("USB OUT missing")
        val inp = bulkIn.get() ?: throw PgpException("USB IN missing")
        val seqByte = (seq.getAndIncrement() and 0xff).toByte()
        val header = ByteBuffer.allocate(10).order(ByteOrder.LITTLE_ENDIAN)
        header.put(0x6F) // PC_to_RDR_XfrBlock
        header.putInt(apdu.size)
        header.put(seqByte)
        header.put(0) // slot
        header.put(0) // bBWI
        header.putShort(0) // level parameter
        val tx = header.array() + apdu
        val wrote = conn.bulkTransfer(out, tx, tx.size, 5_000)
        if (wrote < 0) throw PgpException("USB CCID write failed")
        val rx = ByteArray(1024)
        val read = conn.bulkTransfer(inp, rx, rx.size, 5_000)
        if (read < 10) throw PgpException("USB CCID read failed")
        val dataLen = ByteBuffer.wrap(rx, 1, 4).order(ByteOrder.LITTLE_ENDIAN).int
        val payloadStart = 10
        val payloadEnd = (payloadStart + dataLen).coerceAtMost(read)
        return rx.copyOfRange(payloadStart, payloadEnd)
    }
}
