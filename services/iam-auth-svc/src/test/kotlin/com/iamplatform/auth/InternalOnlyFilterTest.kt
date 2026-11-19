package com.iamplatform.auth

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
    fun `the portal calling straight to the container reaches the enrollment sign-in`() {
        val (response, chain) = call("/internal/login/enrollment")
        assertEquals(200, response.status)
        assertNotNull(chain.request)
    }

    @Test
    fun `any proxy header makes the enrollment sign-in look external and it is answered not found`() {
        for (h in listOf("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-IP")) {
            val (response, chain) = call("/internal/login/enrollment", h to "203.0.113.9")
            assertEquals(404, response.status, h)
            assertNull(chain.request, h)
        }
    }

    @Test
    fun `the public sign-in routes are not affected, with or without proxy headers`() {
        for (uri in listOf("/api/v1/login", "/api/v1/login/precheck", "/api/v1/logout", "/actuator/health")) {
            val (response, chain) = call(uri, "X-Forwarded-For" to "203.0.113.9")
            assertEquals(200, response.status, uri)
            assertNotNull(chain.request, uri)
        }
    }

    @Test
    fun `only paths under the internal prefix are guarded`() {
        assertTrue(InternalOnlyFilter.isGuarded("/internal/login/enrollment"))
        assertFalse(InternalOnlyFilter.isGuarded("/api/v1/login"))
        assertFalse(InternalOnlyFilter.isGuarded("/internalx/login"))
    }
}
