package ltechnologies.onionphone.pgpshield.data

import java.net.HttpURLConnection
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.net.URI
import ltechnologies.onionphone.pgpshield.engine.PgpException

/**
 * Fail-closed HTTP via OnionVPN's local SOCKS proxy.
 *
 * Production keyserver / WKD lookups must never use clearnet. Unit tests may
 * set [bypassForTests] to talk to a loopback fake server.
 */
object TorSocks {
    const val HOST = "127.0.0.1"
    const val PORT = 18202

    @Volatile
    var bypassForTests: Boolean = false

    fun openConnection(url: String, method: String): HttpURLConnection {
        val conn = if (bypassForTests) {
            URI(url).toURL().openConnection() as HttpURLConnection
        } else {
            requireAvailable()
            val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress.createUnresolved(HOST, PORT))
            URI(url).toURL().openConnection(proxy) as HttpURLConnection
        }
        return conn.apply {
            requestMethod = method
            instanceFollowRedirects = false
        }
    }

    fun requireAvailable() {
        if (bypassForTests) return
        try {
            Socket().use { socket ->
                socket.connect(InetSocketAddress(HOST, PORT), 1_500)
            }
        } catch (e: Exception) {
            throw PgpException(
                "Key lookup requires OnionVPN SOCKS at $HOST:$PORT (clearnet blocked)",
                cause = e,
            )
        }
    }
}
