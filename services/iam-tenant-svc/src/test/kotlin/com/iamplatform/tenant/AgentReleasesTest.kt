package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.argThat
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.security.MessageDigest
import java.util.Base64
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AgentReleasesTest {

    private val releases = mock<AgentReleaseRepository>()
    private val packages = mock<AgentReleasePackageRepository>()
    private val service = AgentReleaseService(releases, packages)

    private val bytes = "MSI-BYTES".toByteArray()
    private val sha = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    private fun request(version: String = "0.3.1", hash: String = sha, content: String = Base64.getEncoder().encodeToString(bytes)) =
        PublishAgentReleaseRequest(version, "WINDOWS", "x86_64", hash, "c2ln", "PRODUCTION", content)

    private fun release(version: String, signature: String? = "c2ln") =
        AgentReleaseEntity(UUID.randomUUID(), version, "WINDOWS", "x86_64", "db:x", "h", "k", "PRODUCTION", signature)

    @Test
    fun `versions compare numerically, not as text`() {
        assertTrue(AgentVersions.isNewer("0.10.0", "0.9.9"))
        assertTrue(AgentVersions.isNewer("1.0.0", "0.99.99"))
        assertTrue(AgentVersions.isNewer("0.2.1", "0.2.0"))
        assertFalse(AgentVersions.isNewer("0.2.0", "0.2.0"))
        assertFalse(AgentVersions.isNewer("0.1.9", "0.2.0"))
        assertFalse(AgentVersions.isNewer("garbage", "0.1.0"))
        assertFalse(AgentVersions.isNewer("1.2", "0.1.0"))
    }

    @Test
    fun `publishing stores the release and its package when the checksum matches`() {
        whenever(releases.existsByVersionAndPlatformAndArchitecture(any(), any(), any())).thenReturn(false)
        val offer = service.publish(request())
        assertEquals("0.3.1", offer.version)
        assertEquals(bytes.size.toLong(), offer.sizeBytes)
        verify(releases).save(argThat<AgentReleaseEntity> { checksum == sha && signature == "c2ln" && signingKeyId == "openbao:transit/agent-release" })
        verify(packages).save(argThat<AgentReleasePackageEntity> { content.contentEquals(bytes) })
    }

    @Test
    fun `a checksum that does not match the uploaded bytes is refused and nothing is stored`() {
        assertThrows<AgentReleaseRejectedException> { service.publish(request(hash = "0".repeat(64))) }
        verify(releases, never()).save(any())
        verify(packages, never()).save(any())
    }

    @Test
    fun `bad base64, an empty package and a duplicate version are refused`() {
        assertThrows<AgentReleaseRejectedException> { service.publish(request(content = "!!!")) }
        assertThrows<AgentReleaseRejectedException> { service.publish(request(content = "")) }
        whenever(releases.existsByVersionAndPlatformAndArchitecture("0.3.1", "WINDOWS", "x86_64")).thenReturn(true)
        assertThrows<AgentReleaseRejectedException> { service.publish(request()) }
    }

    @Test
    fun `the offer is the newest production release that is newer than the agent, and needs a signature and a package`() {
        val old = release("0.2.0")
        val mid = release("0.3.0")
        val newest = release("0.10.0")
        val unsigned = release("0.11.0", signature = null)
        whenever(releases.findByPlatformAndArchitectureAndReleaseState("WINDOWS", "x86_64", "PRODUCTION")).thenReturn(listOf(old, newest, unsigned, mid))
        for (r in listOf(old, mid, newest)) whenever(packages.findById(r.id)).thenReturn(Optional.of(AgentReleasePackageEntity(r.id, bytes, bytes.size.toLong())))

        assertEquals("0.10.0", service.offerFor("WINDOWS", "x86_64", "0.2.0")!!.version)
        assertNull(service.offerFor("WINDOWS", "x86_64", "0.10.0"), "nothing newer than the agent's own version")
        assertNull(service.offerFor("WINDOWS", "x86_64", "1.0.0"), "never offers a downgrade")
    }

    @Test
    fun `a release whose package is missing is not offered`() {
        val r = release("0.4.0")
        whenever(releases.findByPlatformAndArchitectureAndReleaseState(any(), any(), any())).thenReturn(listOf(r))
        whenever(packages.findById(r.id)).thenReturn(Optional.empty())
        assertNull(service.offerFor("WINDOWS", "x86_64", "0.2.0"))
    }

    @Test
    fun `package bytes are returned for a known release`() {
        val id = UUID.randomUUID()
        whenever(packages.findById(id)).thenReturn(Optional.of(AgentReleasePackageEntity(id, bytes, 9)))
        assertNotNull(service.packageBytes(id))
        assertNull(service.packageBytes(UUID.randomUUID()))
    }
}
