package com.iamplatform.tenant

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Talks to a real in-process HTTP server (JDK built-in), so the actual requests on the wire are asserted. */
class ScimClientTest {

    private class Seen(val method: String, val path: String, val query: String?, val headers: Map<String, String>, val body: String)

    private class Reply(val status: Int, val body: String = "", val headers: Map<String, String> = emptyMap())

    private val seen = CopyOnWriteArrayList<Seen>()
    private val routes = mutableMapOf<String, Reply>()
    private val server: HttpServer = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0).apply {
        createContext("/") { ex -> handle(ex) }
        start()
    }
    private val base = "http://127.0.0.1:${server.address.port}/scim/v2"
    private val client = ScimClient(OutboundUrlGuard(allowPrivateTargets = true))

    @AfterEach
    fun stop() = server.stop(0)

    private fun handle(ex: HttpExchange) {
        val body = ex.requestBody.readBytes().toString(Charsets.UTF_8)
        val headers = ex.requestHeaders.entries.associate { it.key.lowercase() to it.value.joinToString(",") }
        seen += Seen(ex.requestMethod, ex.requestURI.path, ex.requestURI.rawQuery, headers, body)
        val reply = routes["${ex.requestMethod} ${ex.requestURI.path}"] ?: Reply(404, """{"detail":"no route"}""")
        reply.headers.forEach { (k, v) -> ex.responseHeaders.add(k, v) }
        val bytes = reply.body.toByteArray()
        if (bytes.isEmpty()) ex.sendResponseHeaders(reply.status, -1) else {
            ex.responseHeaders.add("Content-Type", "application/scim+json")
            ex.sendResponseHeaders(reply.status, bytes.size.toLong())
            ex.responseBody.use { it.write(bytes) }
        }
        ex.close()
    }

    private val spec = ScimUserSpec("ada@econz.net", "uuid-1", "Ada Lovelace", "Ada", "Lovelace", active = true)

    @Test
    fun `createUser sends a SCIM core User with a bearer token and returns the app's id`() {
        routes["POST /scim/v2/Users"] = Reply(201, """{"id":"app-77","userName":"ada@econz.net"}""")

        val id = client.createUser(base, "secret-token", spec)

        assertEquals("app-77", id)
        val req = seen.single()
        assertEquals("Bearer secret-token", req.headers["authorization"])
        assertTrue(req.headers["content-type"]!!.startsWith("application/scim+json"))
        assertTrue(req.body.contains("urn:ietf:params:scim:schemas:core:2.0:User"))
        assertTrue(req.body.contains("\"userName\":\"ada@econz.net\""))
        assertTrue(req.body.contains("\"externalId\":\"uuid-1\""))
        assertTrue(req.body.contains("\"givenName\":\"Ada\""))
        assertTrue(req.body.contains("\"active\":true"))
    }

    @Test
    fun `a 409 is reported as a conflict so the caller can link the existing account`() {
        routes["POST /scim/v2/Users"] = Reply(409, """{"detail":"uniqueness"}""")

        val ex = assertThrows<ScimException> { client.createUser(base, "t", spec) }

        assertTrue(ex.conflict)
    }

    @Test
    fun `findIdByUserName filters by userName and returns the first match or null`() {
        routes["GET /scim/v2/Users"] = Reply(200, """{"totalResults":1,"Resources":[{"id":"app-9"}]}""")

        assertEquals("app-9", client.findIdByUserName(base, "t", "ada@econz.net"))
        assertEquals("""userName eq "ada@econz.net"""", URLDecoder.decode(seen.single().query!!.removePrefix("filter="), "UTF-8"))

        routes["GET /scim/v2/Users"] = Reply(200, """{"totalResults":0,"Resources":[]}""")
        assertNull(client.findIdByUserName(base, "t", "nobody@econz.net"))
    }

    @Test
    fun `setActive sends a SCIM PatchOp replacing active`() {
        routes["PATCH /scim/v2/Users/app-1"] = Reply(200, """{"id":"app-1","active":false}""")

        client.setActive(base, "t", "app-1", false)

        val req = seen.single()
        assertTrue(req.body.contains("urn:ietf:params:scim:api:messages:2.0:PatchOp"))
        assertTrue(req.body.contains("\"op\":\"replace\""))
        assertTrue(req.body.contains("\"path\":\"active\""))
        assertTrue(req.body.contains("\"value\":false"))
    }

    @Test
    fun `setActive falls back to GET then PUT for servers without PATCH`() {
        routes["PATCH /scim/v2/Users/app-1"] = Reply(405, """{"detail":"no patch"}""")
        routes["GET /scim/v2/Users/app-1"] = Reply(200, """{"id":"app-1","userName":"ada@econz.net","active":true}""")
        routes["PUT /scim/v2/Users/app-1"] = Reply(200, """{"id":"app-1","active":false}""")

        client.setActive(base, "t", "app-1", false)

        assertEquals(listOf("PATCH", "GET", "PUT"), seen.map { it.method })
        val put = seen.last()
        assertTrue(put.body.contains("\"active\":false"))
        assertTrue(put.body.contains("\"userName\":\"ada@econz.net\""))
    }

    @Test
    fun `deleteUser treats an already-deleted user as done but surfaces real errors`() {
        routes["DELETE /scim/v2/Users/gone"] = Reply(404, """{"detail":"missing"}""")
        client.deleteUser(base, "t", "gone")

        routes["DELETE /scim/v2/Users/broken"] = Reply(500, """{"detail":"boom"}""")
        val ex = assertThrows<ScimException> { client.deleteUser(base, "t", "broken") }
        assertEquals(500, ex.status)
    }

    @Test
    fun `a rejected token is explained in plain words`() {
        routes["GET /scim/v2/ServiceProviderConfig"] = Reply(401, """{"detail":"bad token"}""")

        val ex = assertThrows<ScimException> { client.testConnection(base, "wrong") }

        assertTrue(ex.message!!.contains("rejected the access token"))
        assertFalse(ex.message!!.contains("wrong"), "the token must never appear in an error")
    }

    @Test
    fun `an unreachable app is reported, not thrown as a raw network error`() {
        val dead = ScimClient(OutboundUrlGuard(allowPrivateTargets = true))
        val ex = assertThrows<ScimException> { dead.testConnection("http://127.0.0.1:1/scim/v2", "t") }
        assertTrue(ex.message!!.startsWith("Could not reach the app"))
    }

    @Test
    fun `redirects are never followed`() {
        routes["POST /scim/v2/Users"] = Reply(302, "", mapOf("Location" to "http://127.0.0.1:${server.address.port}/elsewhere"))

        assertThrows<ScimException> { client.createUser(base, "t", spec) }

        assertTrue(seen.none { it.path == "/elsewhere" }, "the redirect target must not be requested")
    }

    @Test
    fun `an internal target is refused before any request is made when the guard is strict`() {
        val strict = ScimClient(OutboundUrlGuard(allowPrivateTargets = false))

        assertThrows<ScimException> { strict.testConnection(base, "t") }

        assertTrue(seen.isEmpty())
    }
}
