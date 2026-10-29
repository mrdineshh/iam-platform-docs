package com.iamplatform.auth

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class ClientContextTest {

    @Test
    fun `the proxy's forwarded address wins over whatever the body claims`() {
        assertEquals("27.34.250.10", ClientContext.ip("27.34.250.10", bodyIp = "1.2.3.4", remoteAddr = "172.18.0.1"))
    }

    @Test
    fun `with several hops the last one -- the address the proxy itself saw -- is used`() {
        assertEquals("27.34.250.10", ClientContext.ip("1.2.3.4, 5.6.7.8, 27.34.250.10", bodyIp = "9.9.9.9", remoteAddr = null))
    }

    @Test
    fun `an internal caller with no forwarded header falls back to the ip it supplied`() {
        assertEquals("27.34.250.10", ClientContext.ip(null, bodyIp = "27.34.250.10", remoteAddr = "172.18.0.5"))
        assertEquals("27.34.250.10", ClientContext.ip("  ", bodyIp = "27.34.250.10", remoteAddr = "172.18.0.5"))
    }

    @Test
    fun `with nothing else it uses the socket address, and strips an IPv4-mapped IPv6 prefix`() {
        assertEquals("172.18.0.5", ClientContext.ip(null, bodyIp = "", remoteAddr = "172.18.0.5"))
        assertEquals("8.8.8.8", ClientContext.ip("::ffff:8.8.8.8", bodyIp = null, remoteAddr = null))
    }

    @Test
    fun `user agent prefers the forwarded one, falls back to the header, and is length-capped`() {
        assertEquals("Mozilla/5.0 Chrome", ClientContext.userAgent("Mozilla/5.0 Chrome", "node"))
        assertEquals("Mozilla/5.0 Chrome", ClientContext.userAgent(null, "Mozilla/5.0 Chrome"))
        assertNull(ClientContext.userAgent(" ", ""))
        assertEquals(512, ClientContext.userAgent("x".repeat(2000), null)!!.length)
    }
}
