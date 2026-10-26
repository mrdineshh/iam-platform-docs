package com.iamplatform.geo

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GeoLookupServiceTest {

    private val service = GeoLookupService()

    @Test
    fun `resolves a known real IP to its real country`() {
        val result = service.resolve("8.8.8.8")
        assertTrue(result.resolved)
        assertEquals("US", result.country)
    }

    @Test
    fun `resolves another known real IP`() {
        val result = service.resolve("1.1.1.1")
        assertTrue(result.resolved)
        assertEquals("AU", result.country)
    }

    @Test
    fun `region and city are always null -- country-lite carries no sub-country data`() {
        val result = service.resolve("8.8.8.8")
        assertNull(result.region)
        assertNull(result.city)
    }

    @Test
    fun `returns unresolved, not an error, for a reserved never-routed IP`() {
        // 203.0.113.0/24 is RFC 5737 TEST-NET-3 -- permanently reserved, never
        // publicly announced, so it never appears in real geo data.
        val result = service.resolve("203.0.113.5")
        assertFalse(result.resolved)
        assertNull(result.country)
    }

    @Test
    fun `rejects a malformed IP`() {
        assertThrows<InvalidIpException> {
            service.resolve("not-an-ip")
        }
    }
}
