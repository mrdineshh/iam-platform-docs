package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.argThat
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeviceLoginRuleServiceTest {

    private val rules = mock<TenantDeviceLoginRuleRepository>()
    private val devices = mock<IamDeviceRepository>()
    private val posture = mock<DevicePostureRepository>()
    private val auditPublisher = mock<AuditPublisher>()
    private val gate = TrustedDeviceGate(mock<OidcClientRepository>(), mock<SamlSpRepository>(), devices, posture, auditPublisher)
    private val service = DeviceLoginRuleService(rules, gate, auditPublisher)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val deviceId = UUID.randomUUID()

    private fun ruleOn(on: Boolean = true) {
        whenever(rules.findById(tenantId)).thenReturn(Optional.of(TenantDeviceLoginRuleEntity(tenantId, on)))
    }

    private fun device(status: String = "APPROVED", owner: UUID = userId, exceptionUntil: Instant? = null) {
        whenever(devices.findById(deviceId)).thenReturn(
            Optional.of(
                IamDeviceEntity(deviceId, tenantId, owner, UUID.randomUUID(), ownership = "BYOD", lifecycleStatus = status, complianceExceptionUntil = exceptionUntil),
            ),
        )
    }

    private fun posture(status: String) {
        whenever(posture.findById(deviceId)).thenReturn(Optional.of(DevicePostureEntity(deviceId, status)))
    }

    private fun check(role: String = "USER", device: UUID? = deviceId) =
        service.check(LoginDeviceCheckRequest(tenantId, userId, role, device?.toString()))

    @Test
    fun `with no rule row the sign-in is allowed and no device is even looked at`() {
        assertTrue(check(device = null).allowed)
        verify(devices, never()).findById(any())
    }

    @Test
    fun `with the rule switched off the sign-in is allowed`() {
        ruleOn(false)
        assertTrue(check(device = null).allowed)
    }

    @Test
    fun `administrators are never held to the rule, so a broken laptop cannot lock them out`() {
        ruleOn()
        assertTrue(check(role = "ADMIN", device = null).allowed)
        assertTrue(check(role = "admin", device = null).allowed)
        verify(devices, never()).findById(any())
    }

    @Test
    fun `a user with no verified device is refused as DEVICE_REQUIRED`() {
        ruleOn()
        val answer = check(device = null)
        assertFalse(answer.allowed)
        assertEquals("DEVICE_REQUIRED", answer.code)
    }

    @Test
    fun `a device that is not registered, or belongs to someone else, counts as no device`() {
        ruleOn()
        assertEquals("DEVICE_REQUIRED", check().code) // unknown id
        device(owner = UUID.randomUUID()); posture("COMPLIANT")
        assertEquals("DEVICE_REQUIRED", check().code)
    }

    @Test
    fun `an approved compliant laptop is allowed, with nothing audited`() {
        ruleOn(); device(); posture("COMPLIANT")
        assertTrue(check().allowed)
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `a laptop that is not yet approved is refused even though an app could allow pending devices`() {
        ruleOn(); device(status = "PENDING_APPROVAL"); posture("COMPLIANT")
        val answer = check()
        assertEquals("DEVICE_NOT_APPROVED", answer.code)
        assertEquals("pending approval", answer.detail)
    }

    @Test
    fun `suspended, revoked, rejected and decommissioned laptops are refused`() {
        ruleOn(); posture("COMPLIANT")
        for (status in listOf("SUSPENDED", "REVOKED", "REJECTED", "DECOMMISSIONED")) {
            device(status = status)
            assertEquals("DEVICE_NOT_APPROVED", check().code, status)
        }
    }

    @Test
    fun `a non-compliant laptop is refused as DEVICE_NON_COMPLIANT`() {
        ruleOn(); device(); posture("NON_COMPLIANT")
        assertEquals("DEVICE_NON_COMPLIANT", check().code)
    }

    @Test
    fun `an active compliance exception lets a non-compliant laptop sign in, and the use is audited`() {
        ruleOn(); device(exceptionUntil = Instant.now().plusSeconds(3600)); posture("NON_COMPLIANT")
        assertTrue(check().allowed)
        verify(auditPublisher).publish(argThat<AuditEvent> { action == "auth.login.allowed_compliance_exception" })
    }

    @Test
    fun `an expired compliance exception does not help`() {
        ruleOn(); device(exceptionUntil = Instant.now().minusSeconds(60)); posture("NON_COMPLIANT")
        assertEquals("DEVICE_NON_COMPLIANT", check().code)
    }

    @Test
    fun `switching the rule on is stored and audited, and doing it again changes nothing`() {
        service.set(tenantId, true, "admin-1", "1.2.3.4")
        verify(rules).save(argThat<TenantDeviceLoginRuleEntity> { requireTrustedDevice && updatedBy == "admin-1" })
        verify(auditPublisher).publish(argThat<AuditEvent> { action == "tenant.device_login_rule.enabled" })

        ruleOn()
        whenever(rules.existsById(tenantId)).thenReturn(true)
        service.set(tenantId, true, "admin-1", "1.2.3.4")
        verify(auditPublisher, org.mockito.kotlin.times(1)).publish(any())
    }

    @Test
    fun `an unknown tenant reads as off`() {
        assertFalse(service.isRequired(UUID.randomUUID()))
    }
}
