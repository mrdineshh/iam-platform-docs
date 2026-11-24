package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.doThrow
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TenantControllerOnboardingTest {

    private val tenants = mock<TenantService>()
    private val branding = mock<TenantBrandingService>()
    private val guard = mock<AdminAccessGuard>()
    private val controller = TenantController(tenants, branding, guard, "econz")
    private val request = CreateTenantRequest("Acme", "acme")
    private val operatorId = UUID.randomUUID()

    private fun operatorExists() {
        whenever(tenants.getTenantBySubdomain("econz")).thenReturn(TenantEntity(operatorId, "Econz", "econz"))
    }

    @Test
    fun `an administrator of another organization cannot onboard one`() {
        operatorExists()
        whenever(guard.requireTenantAdmin("token", operatorId)).doThrow(AdminAccessDeniedException("session does not belong to this tenant"))
        assertFailsWith<AdminAccessDeniedException> { controller.createTenant(request, "token") }
        verify(tenants, never()).createTenant(any())
    }

    @Test
    fun `a non-administrator of the operator organization cannot onboard one`() {
        operatorExists()
        whenever(guard.requireTenantAdmin("token", operatorId)).doThrow(AdminAccessDeniedException("admin role required"))
        assertFailsWith<AdminAccessDeniedException> { controller.createTenant(request, "token") }
        verify(tenants, never()).createTenant(any())
    }

    @Test
    fun `an unknown or expired session cannot onboard one`() {
        whenever(guard.requireValidSession("token")).doThrow(AdminSessionInvalidException())
        assertFailsWith<AdminSessionInvalidException> { controller.createTenant(request, "token") }
        verify(tenants, never()).createTenant(any())
    }

    @Test
    fun `when the operator organization does not exist nobody can onboard one`() {
        whenever(guard.requireValidSession("token")).thenReturn(RemoteSession(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), Instant.now()))
        whenever(tenants.getTenantBySubdomain("econz")).thenThrow(TenantSubdomainNotFoundException("econz"))
        assertFailsWith<AdminAccessDeniedException> { controller.createTenant(request, "token") }
        verify(tenants, never()).createTenant(any())
    }

    @Test
    fun `can-onboard is true only for an administrator of the operator organization`() {
        operatorExists()
        assertTrue(controller.canOnboard("token").body!!.allowed)
        whenever(guard.requireTenantAdmin("other", operatorId)).doThrow(AdminAccessDeniedException("no"))
        assertFalse(controller.canOnboard("other").body!!.allowed)
        whenever(guard.requireValidSession("bad")).doThrow(AdminSessionInvalidException())
        assertFalse(controller.canOnboard("bad").body!!.allowed)
    }
}
