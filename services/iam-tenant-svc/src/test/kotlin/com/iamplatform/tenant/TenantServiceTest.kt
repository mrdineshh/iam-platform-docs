package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals

class TenantServiceTest {

    private val repository = mock<TenantRepository>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = TenantService(repository, auditPublisher)

    @Test
    fun `createTenant saves the tenant and publishes tenant-created`() {
        whenever(repository.existsBySubdomain("acme")).thenReturn(false)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.createTenant(CreateTenantRequest(name = "Acme Inc", subdomain = "acme"))

        assertEquals("Acme Inc", result.name)
        assertEquals("acme", result.subdomain)
        assertEquals(TenantStatus.ACTIVE, result.status)

        verify(auditPublisher, times(1)).publish(any<AuditEvent>())
    }

    @Test
    fun `createTenant rejects a duplicate subdomain and does not publish`() {
        whenever(repository.existsBySubdomain("acme")).thenReturn(true)

        assertThrows<SubdomainAlreadyExistsException> {
            service.createTenant(CreateTenantRequest(name = "Acme Inc", subdomain = "acme"))
        }

        verify(repository, never()).save(any())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `getTenant throws when the tenant does not exist`() {
        val id = UUID.randomUUID()
        whenever(repository.findById(id)).thenReturn(Optional.empty())

        assertThrows<TenantNotFoundException> {
            service.getTenant(id)
        }
    }

    @Test
    fun `getTenantBySubdomain returns the matching tenant`() {
        val tenant = TenantEntity(id = UUID.randomUUID(), name = "Acme Inc", subdomain = "acme")
        whenever(repository.findBySubdomain("acme")).thenReturn(tenant)

        val result = service.getTenantBySubdomain("acme")

        assertEquals(tenant.id, result.id)
    }

    @Test
    fun `getTenantBySubdomain throws when no tenant matches`() {
        whenever(repository.findBySubdomain("ghost")).thenReturn(null)

        assertThrows<TenantSubdomainNotFoundException> {
            service.getTenantBySubdomain("ghost")
        }
    }
}
