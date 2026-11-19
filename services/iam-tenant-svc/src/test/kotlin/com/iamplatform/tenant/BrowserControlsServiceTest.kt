package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.argThat
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BrowserControlsServiceTest {

    private val repo = mock<TenantBrowserControlsRepository>()
    private val audit = mock<AuditPublisher>()
    private val service = BrowserControlsService(repo, audit)
    private val tenantId = UUID.randomUUID()

    private fun row(blocked: Boolean) {
        whenever(repo.findById(tenantId)).thenReturn(Optional.of(TenantBrowserControlsEntity(tenantId, blocked)))
    }

    @Test
    fun `a tenant that never chose reads as not blocking`() {
        assertFalse(service.isBlockingPersonalMicrosoft(tenantId))
    }

    @Test
    fun `it reads what was stored`() {
        row(true)
        assertTrue(service.isBlockingPersonalMicrosoft(tenantId))
        row(false)
        assertFalse(service.isBlockingPersonalMicrosoft(tenantId))
    }

    @Test
    fun `switching on stores it with who did it and audits it`() {
        service.setBlockPersonalMicrosoft(tenantId, true, "admin-1", "1.2.3.4")
        verify(repo).save(argThat<TenantBrowserControlsEntity> { blockPersonalMicrosoft && updatedBy == "admin-1" })
        verify(audit).publish(argThat<AuditEvent> { action == "tenant.browser_controls.personal_microsoft_block.enabled" && actorId == "admin-1" })
    }

    @Test
    fun `switching off an enabled tenant is stored and audited`() {
        row(true)
        service.setBlockPersonalMicrosoft(tenantId, false, "admin-2", null)
        verify(repo).save(argThat<TenantBrowserControlsEntity> { !blockPersonalMicrosoft })
        verify(audit).publish(argThat<AuditEvent> { action == "tenant.browser_controls.personal_microsoft_block.disabled" })
    }

    @Test
    fun `setting what it already is changes nothing and records nothing`() {
        row(true)
        service.setBlockPersonalMicrosoft(tenantId, true, "admin-1", null)
        verify(repo, never()).save(any<TenantBrowserControlsEntity>())
        verify(audit, never()).publish(any())
    }

    @Test
    fun `switching off a tenant that never chose creates no row and no audit`() {
        service.setBlockPersonalMicrosoft(tenantId, false, "admin-1", null)
        verify(repo, never()).save(any<TenantBrowserControlsEntity>())
        verify(audit, never()).publish(any())
        assertEquals(false, service.isBlockingPersonalMicrosoft(tenantId))
    }

    @Test
    fun `one audit event per real change`() {
        service.setBlockPersonalMicrosoft(tenantId, true, "admin-1", null)
        verify(audit, times(1)).publish(any())
    }
}
