package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.vault.OpenBaoClient
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.inOrder
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ScimConnectionServiceTest {

    private val connections = mock<ScimConnectionRepository>()
    private val accounts = mock<ProvisionedAccountRepository>()
    private val tenantRepository = mock<TenantRepository>()
    private val oidcClients = mock<OidcClientRepository>()
    private val samlSps = mock<SamlSpRepository>()
    private val provisioning = mock<ProvisioningService>()
    private val scim = mock<ScimClient>()
    private val openBao = mock<OpenBaoClient>()
    private val auditPublisher = mock<AuditPublisher>()
    // Strict guard (real rules), literal public IPs so the tests need no DNS.
    private val urlGuard = OutboundUrlGuard(allowPrivateTargets = false)
    private val service = ScimConnectionService(
        connections, accounts, tenantRepository, oidcClients, samlSps, provisioning, scim, urlGuard, openBao, auditPublisher,
    )

    private val tenantId = UUID.randomUUID()
    private val adminId = UUID.randomUUID()
    private val appId = UUID.randomUUID()
    private val publicUrl = "https://93.184.216.34/scim/v2/"

    init {
        whenever(tenantRepository.existsById(tenantId)).thenReturn(true)
        whenever(oidcClients.findById(appId)).thenReturn(Optional.of(OidcClientEntity(appId, tenantId, "Pulse", "h", "https://p/cb")))
        whenever(connections.findByTenantIdAndAppKindAndAppId(tenantId, "OIDC", appId)).thenReturn(null)
        whenever(connections.save(any<ScimConnectionEntity>())).thenAnswer { it.arguments[0] }
        whenever(accounts.findByConnectionId(any())).thenReturn(emptyList())
        whenever(provisioning.appName(any())).thenReturn("Pulse")
        whenever(provisioning.tokenFor(any())).thenReturn("tok")
    }

    private fun request(url: String = publicUrl, token: String? = "secret", appKind: String = "OIDC") =
        UpsertScimConnectionRequest(tenantId, appKind, appId, url, token)

    @Test
    fun `a new connection stores the token in the secret store first, then the row, and strips the trailing slash`() {
        val view = service.upsert(request(), adminId)

        assertEquals("https://93.184.216.34/scim/v2", view.baseUrl)
        inOrder(openBao, connections) {
            verify(openBao).writeSecret(eq("scim/${view.id}"), eq(mapOf("token" to "secret")))
            verify(connections).save(any<ScimConnectionEntity>())
        }
    }

    @Test
    fun `if the secret store refuses the token, nothing is saved`() {
        whenever(openBao.writeSecret(any(), any())).thenThrow(IllegalStateException("403 from the secret store"))

        assertThrows<IllegalStateException> { service.upsert(request(), adminId) }

        verify(connections, never()).save(any<ScimConnectionEntity>())
    }

    @Test
    fun `a private or non-https address is refused before anything is stored`() {
        for (bad in listOf("http://93.184.216.34/scim", "https://10.0.0.5/scim", "https://169.254.169.254/", "https://localhost/scim")) {
            assertThrows<InvalidProvisioningTargetException>(bad) { service.upsert(request(url = bad), adminId) }
        }
        verify(openBao, never()).writeSecret(any(), any())
        verify(connections, never()).save(any<ScimConnectionEntity>())
    }

    @Test
    fun `a new connection needs a token`() {
        assertThrows<InvalidProvisioningTargetException> { service.upsert(request(token = null), adminId) }
        assertThrows<InvalidProvisioningTargetException> { service.upsert(request(token = "   "), adminId) }
        verify(connections, never()).save(any<ScimConnectionEntity>())
    }

    @Test
    fun `updating an existing connection without a token keeps the stored one`() {
        val existing = ScimConnectionEntity(UUID.randomUUID(), tenantId, "OIDC", appId, "https://93.184.216.34/old")
        whenever(connections.findByTenantIdAndAppKindAndAppId(tenantId, "OIDC", appId)).thenReturn(existing)

        val view = service.upsert(request(token = null), adminId)

        assertEquals(existing.id, view.id)
        assertEquals("https://93.184.216.34/scim/v2", view.baseUrl)
        verify(openBao, never()).writeSecret(any(), any())
    }

    @Test
    fun `an app that does not belong to this tenant cannot be connected`() {
        whenever(oidcClients.findById(appId)).thenReturn(Optional.of(OidcClientEntity(appId, UUID.randomUUID(), "Other", "h", "https://p/cb")))

        assertThrows<InvalidProvisioningTargetException> { service.upsert(request(), adminId) }
        whenever(oidcClients.findById(appId)).thenReturn(Optional.empty())
        assertThrows<InvalidProvisioningTargetException> { service.upsert(request(), adminId) }
        verify(connections, never()).save(any<ScimConnectionEntity>())
    }

    @Test
    fun `the access token is never part of what the API returns`() {
        val view = service.upsert(request(token = "super-secret-token"), adminId)

        assertFalse(view.toString().contains("super-secret-token"))
        assertTrue(view.hasToken)
    }

    @Test
    fun `removing a connection blanks its stored token and deletes the row`() {
        val existing = ScimConnectionEntity(UUID.randomUUID(), tenantId, "OIDC", appId, "https://93.184.216.34/scim")
        whenever(connections.findById(existing.id)).thenReturn(Optional.of(existing))

        service.delete(tenantId, existing.id, adminId)

        verify(openBao).writeSecret(eq("scim/${existing.id}"), eq(mapOf("token" to "")))
        verify(connections).delete(existing)
    }

    @Test
    fun `a connection of another tenant is not found`() {
        val foreign = ScimConnectionEntity(UUID.randomUUID(), UUID.randomUUID(), "OIDC", appId, "https://93.184.216.34/scim")
        whenever(connections.findById(foreign.id)).thenReturn(Optional.of(foreign))

        assertThrows<ScimConnectionNotFoundException> { service.delete(tenantId, foreign.id, adminId) }
        assertThrows<ScimConnectionNotFoundException> { service.test(tenantId, foreign.id) }
        verify(connections, never()).delete(any<ScimConnectionEntity>())
    }

    @Test
    fun `testing reports success, a missing token, and the app's error in plain words`() {
        val existing = ScimConnectionEntity(UUID.randomUUID(), tenantId, "OIDC", appId, "https://93.184.216.34/scim")
        whenever(connections.findById(existing.id)).thenReturn(Optional.of(existing))

        assertTrue(service.test(tenantId, existing.id).ok)

        whenever(scim.testConnection(any(), any())).thenThrow(ScimException("The app answered HTTP 401 (the app rejected the access token)", 401))
        val rejected = service.test(tenantId, existing.id)
        assertFalse(rejected.ok)
        assertTrue(rejected.message.contains("rejected the access token"))

        whenever(provisioning.tokenFor(any())).thenReturn(null)
        assertTrue(service.test(tenantId, existing.id).message.contains("No access token"))
    }
}
