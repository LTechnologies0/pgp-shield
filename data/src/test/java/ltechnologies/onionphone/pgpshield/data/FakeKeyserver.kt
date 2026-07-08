package ltechnologies.onionphone.pgpshield.data

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.net.InetSocketAddress
import java.net.URLDecoder
import org.json.JSONObject

class FakeKeyserver(
    private val lookupBody: ByteArray,
) : AutoCloseable {
    private val server: HttpServer = HttpServer.create(InetSocketAddress(0), 0)
    var uploadedKey: ByteArray? = null
        private set
    val baseUrl: String
        get() = "http://127.0.0.1:${server.address.port}"

    init {
        server.createContext("/pks/lookup") { exchange -> respond(exchange, lookupBody) }
        server.createContext("/vks/v1/by-fingerprint") { exchange -> respond(exchange, lookupBody) }
        server.createContext("/vks/v1/by-keyid") { exchange -> respond(exchange, lookupBody) }
        server.createContext("/vks/v1/by-email") { exchange -> respond(exchange, lookupBody) }
        server.createContext("/pks/add") { exchange ->
            val body = exchange.requestBody.readBytes().toString(Charsets.UTF_8)
            uploadedKey = parseUploadedArmored(body)?.toByteArray(Charsets.UTF_8)
            respond(exchange, "ok".toByteArray())
        }
        server.createContext("/vks/v1/upload") { exchange ->
            val body = exchange.requestBody.readBytes().toString(Charsets.UTF_8)
            uploadedKey = JSONObject(body).optString("keytext").toByteArray(Charsets.UTF_8)
            val response = JSONObject()
                .put("key_fpr", "ABCD1234")
                .put("status", JSONObject())
                .put("token", "test-token")
            respondJson(exchange, response.toString())
        }
        server.start()
    }

    private fun parseUploadedArmored(body: String): String? {
        if (body.contains("keytext=")) {
            return URLDecoder.decode(body.substringAfter("keytext="), Charsets.UTF_8)
        }
        if (body.contains("key=")) {
            return URLDecoder.decode(body.substringAfter("key="), Charsets.UTF_8)
        }
        return null
    }

    private fun respond(exchange: HttpExchange, body: ByteArray) {
        exchange.responseHeaders.add("Content-Type", "application/pgp-keys")
        exchange.sendResponseHeaders(200, body.size.toLong())
        exchange.responseBody.use { it.write(body) }
        exchange.close()
    }

    private fun respondJson(exchange: HttpExchange, json: String) {
        val bytes = json.toByteArray(Charsets.UTF_8)
        exchange.responseHeaders.add("Content-Type", "application/json")
        exchange.sendResponseHeaders(200, bytes.size.toLong())
        exchange.responseBody.use { it.write(bytes) }
        exchange.close()
    }

    override fun close() {
        server.stop(0)
    }
}
