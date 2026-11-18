package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class InternalOnlyFilterTest {

    private val filter = InternalOnlyFilter()

    private fun call(uri: String, vararg headers: Pair<String, String>): Pair<MockHttpServletResponse, MockFilterChain> {
        val request = MockHttpServletRequest("POST", uri).apply { requestURI = uri; headers.forEach { (k, v) -> addHeader(k, v) } }
        val response = MockHttpServletResponse()
        val chain = MockFilterChain()
        filter.doFilter(request, response, chain)
        return response to chain
    }

    @Test
    fun `a service-to-service call with no proxy header reaches the controller`() {
        val (response, chain) = call("/internal/device-challenges")
        assertEquals(200, response.status)
        assertNotNull(chain.request)
    }

    @Test
    fun `the verify route is guarded too`() {
        val (response, chain) = call("/internal/device-challenges/3f2b1a9e-0000-4000-8000-000000000000/verify", "X-Forwarded-For" to "203.0.113.9")
        assertEquals(404, response.status)
        assertNull(chain.request)
    }

    @Test
    fun `any proxy header makes the request look external and it is answered not found`() {
        for (h in listOf("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-IP")) {
            val (response, chain) = call("/internal/device-challenges", h to "x")
            assertEquals(404, response.status, h)
            assertNull(chain.request, h)
        }
    }

    @Test
    fun `other routes are not affected, with or without proxy headers`() {
        for (uri in listOf("/api/v1/endpoint/devices", "/internal/devices/abc", "/actuator/health")) {
            val (response, chain) = call(uri, "X-Forwarded-For" to "203.0.113.9")
            assertEquals(200, response.status, uri)
            assertNotNull(chain.request, uri)
        }
    }

    @Test
    fun `only the exact guarded prefix is matched`() {
        assertTrue(InternalOnlyFilter.isGuarded("/internal/device-challenges"))
        assertTrue(InternalOnlyFilter.isGuarded("/internal/device-challenges/abc/verify"))
        assertFalse(InternalOnlyFilter.isGuarded("/internal/device-challengesX"))
        assertFalse(InternalOnlyFilter.isGuarded("/internal/devices/abc"))
        assertTrue(InternalOnlyFilter.isGuarded("/internal/agent-releases"))
        assertFalse(InternalOnlyFilter.isGuarded("/api/v1/endpoint/devices/x/agent-update"))
    }
}
