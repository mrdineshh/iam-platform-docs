package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals

class OutboundUrlGuardTest {

    private val strict = OutboundUrlGuard(allowPrivateTargets = false)

    private fun assertBlocked(url: String) {
        assertThrows<InvalidProvisioningTargetException>("should block $url") { strict.validate(url) }
    }

    @Test
    fun `accepts an https URL on a public address`() {
        // A literal public IP, so the test needs no DNS.
        assertEquals("https://93.184.216.34/scim/v2", strict.validate("https://93.184.216.34/scim/v2").toString())
    }

    @Test
    fun `blocks plain http`() {
        assertBlocked("http://93.184.216.34/scim")
    }

    @Test
    fun `blocks loopback and localhost`() {
        assertBlocked("https://127.0.0.1/scim")
        assertBlocked("https://localhost/scim")
        assertBlocked("https://[::1]/scim")
    }

    @Test
    fun `blocks private network ranges, including the internal service names`() {
        assertBlocked("https://10.0.0.5/scim")
        assertBlocked("https://172.16.4.4/scim")
        assertBlocked("https://192.168.1.10/scim")
    }

    @Test
    fun `blocks the cloud metadata address and other link-local addresses`() {
        assertBlocked("https://169.254.169.254/latest/meta-data")
        assertBlocked("https://[fe80::1]/scim")
    }

    @Test
    fun `blocks carrier-grade NAT, unique-local IPv6 and the unspecified address`() {
        assertBlocked("https://100.64.0.1/scim")
        assertBlocked("https://100.127.255.254/scim")
        assertBlocked("https://[fd00::1]/scim")
        assertBlocked("https://0.0.0.0/scim")
    }

    @Test
    fun `blocks credentials in the URL, other schemes, and unparseable input`() {
        assertBlocked("https://user:pass@93.184.216.34/scim")
        assertBlocked("ftp://93.184.216.34/scim")
        assertBlocked("not a url")
        assertBlocked("https:///nohost")
        assertBlocked("")
    }

    @Test
    fun `an unresolvable host is rejected rather than trusted`() {
        assertBlocked("https://this-host-does-not-exist.invalid/scim")
    }

    @Test
    fun `the development switch allows http and private addresses`() {
        val dev = OutboundUrlGuard(allowPrivateTargets = true)
        assertEquals("http://127.0.0.1:9999/scim/v2", dev.validate("http://127.0.0.1:9999/scim/v2").toString())
        assertThrows<InvalidProvisioningTargetException> { dev.validate("ftp://127.0.0.1/scim") }
    }
}
