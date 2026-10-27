package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AppAccessServiceTest {

    private val oidcClients = mock<OidcClientRepository>()
    private val samlSps = mock<SamlSpRepository>()
    private val oidcGroups = mock<OidcClientGroupRepository>()
    private val samlGroups = mock<SamlSpGroupRepository>()
    private val service = AppAccessService(oidcClients, samlSps, oidcGroups, samlGroups)

    private val tenantId = UUID.randomUUID()
    private val pulseId = UUID.randomUUID()
    private val googleId = UUID.randomUUID()
    private val group1 = UUID.randomUUID()
    private val otherGroup = UUID.randomUUID()

    init {
        whenever(oidcClients.findById(pulseId)).thenReturn(Optional.of(OidcClientEntity(pulseId, tenantId, "Pulse", "h", "https://p/cb")))
        whenever(samlSps.findById(googleId)).thenReturn(Optional.of(SamlSpEntity(googleId, tenantId, "Google Workspace", "e", "https://g/acs")))
        whenever(oidcGroups.findByOidcClientId(pulseId)).thenReturn(listOf(OidcClientGroupEntity(UUID.randomUUID(), pulseId, group1)))
        whenever(samlGroups.findBySamlSpId(googleId)).thenReturn(listOf(SamlSpGroupEntity(UUID.randomUUID(), googleId, group1)))
    }

    @Test
    fun `a user in a group assigned to the app is allowed, OIDC and SAML`() {
        assertTrue(service.check(tenantId, RemoteUserRole.USER, group1, "oidc", pulseId).allowed)
        assertTrue(service.check(tenantId, RemoteUserRole.USER, group1, "saml", googleId).allowed)
    }

    @Test
    fun `a user in a different group is refused`() {
        val result = service.check(tenantId, RemoteUserRole.USER, otherGroup, "oidc", pulseId)

        assertFalse(result.allowed)
        assertEquals("your group does not have access to this app", result.reason)
    }

    @Test
    fun `a user with no group is refused`() {
        assertFalse(service.check(tenantId, RemoteUserRole.USER, null, "saml", googleId).allowed)
    }

    @Test
    fun `an app with no groups assigned is closed to regular users`() {
        whenever(oidcGroups.findByOidcClientId(pulseId)).thenReturn(emptyList())

        assertFalse(service.check(tenantId, RemoteUserRole.USER, group1, "oidc", pulseId).allowed)
    }

    @Test
    fun `an admin may open every app of their organization, even with no group`() {
        whenever(oidcGroups.findByOidcClientId(pulseId)).thenReturn(emptyList())

        assertTrue(service.check(tenantId, RemoteUserRole.ADMIN, null, "oidc", pulseId).allowed)
        assertTrue(service.check(tenantId, RemoteUserRole.ADMIN, null, "saml", googleId).allowed)
    }

    @Test
    fun `an app of another organization is refused even for an admin`() {
        val result = service.check(UUID.randomUUID(), RemoteUserRole.ADMIN, null, "oidc", pulseId)

        assertFalse(result.allowed)
        assertEquals("app belongs to another organization", result.reason)
    }

    @Test
    fun `an unknown app or app type is refused`() {
        whenever(oidcClients.findById(UUID.fromString("00000000-0000-0000-0000-000000000001"))).thenReturn(Optional.empty())

        assertFalse(service.check(tenantId, RemoteUserRole.ADMIN, null, "oidc", UUID.fromString("00000000-0000-0000-0000-000000000001")).allowed)
        assertFalse(service.check(tenantId, RemoteUserRole.ADMIN, null, "ldap", pulseId).allowed)
    }

    @Test
    fun `the app type is matched case-insensitively`() {
        assertTrue(service.check(tenantId, RemoteUserRole.USER, group1, "OIDC", pulseId).allowed)
    }
}
