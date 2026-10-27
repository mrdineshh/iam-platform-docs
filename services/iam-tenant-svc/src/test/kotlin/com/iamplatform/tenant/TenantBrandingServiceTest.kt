package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNull

class TenantBrandingServiceTest {

    private val repository = mock<TenantBrandingRepository>()
    private val tenantRepository = mock<TenantRepository>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = TenantBrandingService(repository, tenantRepository, auditPublisher)

    private val tenantId = UUID.randomUUID()
    private val adminId = UUID.randomUUID()

    private fun givenTenantExists() {
        whenever(tenantRepository.existsById(tenantId)).thenReturn(true)
        whenever(repository.findById(tenantId)).thenReturn(Optional.empty())
        whenever(repository.save(any<TenantBrandingEntity>())).thenAnswer { it.arguments[0] }
    }

    @Test
    fun `rejects an unknown tenant without saving`() {
        whenever(tenantRepository.existsById(tenantId)).thenReturn(false)

        assertThrows<TenantNotFoundException> {
            service.update(UpdateBrandingRequest(tenantId, primaryColor = "#112233"), adminId, "1.2.3.4")
        }
        verify(repository, never()).save(any<TenantBrandingEntity>())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `saves a normalized branding and audits it with the admin as actor`() {
        givenTenantExists()

        val saved = service.update(
            UpdateBrandingRequest(tenantId, "#AABBCC", " https://cdn.example.com/logo.png ", "  Welcome back  ", "dark"),
            adminId,
            "1.2.3.4",
        )

        assertEquals("#aabbcc", saved.primaryColor)
        assertEquals("https://cdn.example.com/logo.png", saved.logoUrl)
        assertEquals("Welcome back", saved.headline)
        assertEquals("dark", saved.defaultTheme)

        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("tenant.branding_updated", captor.firstValue.action)
        assertEquals(ActorType.ADMIN, captor.firstValue.actorType)
        assertEquals(adminId.toString(), captor.firstValue.actorId)
    }

    @Test
    fun `all-null request resets the tenant to the default theme`() {
        givenTenantExists()

        val saved = service.update(UpdateBrandingRequest(tenantId), adminId, null)

        assertNull(saved.primaryColor)
        assertNull(saved.logoUrl)
        assertNull(saved.headline)
        assertNull(saved.defaultTheme)
    }

    @Test
    fun `a blank headline and blank logo are stored as null`() {
        givenTenantExists()

        val saved = service.update(UpdateBrandingRequest(tenantId, headline = "   ", logoUrl = "  "), adminId, null)

        assertNull(saved.headline)
        assertNull(saved.logoUrl)
    }

    @Test
    fun `rejects a logo url that is not a valid https url even if it slipped past bean validation`() {
        givenTenantExists()

        assertThrows<InvalidBrandingException> {
            service.update(UpdateBrandingRequest(tenantId, logoUrl = "http://cdn.example.com/logo.png"), adminId, null)
        }
        assertThrows<InvalidBrandingException> {
            service.update(UpdateBrandingRequest(tenantId, logoUrl = "https://"), adminId, null)
        }
        verify(repository, never()).save(any<TenantBrandingEntity>())
    }
}
