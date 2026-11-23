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
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DeviceLoginRuleServiceTest {

    private val rules = mock<TenantDeviceLoginRuleRepository>()
    private val devices = mock<IamDeviceRepository>()
    private val posture = mock<DevicePostureRepository>()
    private val auditPublisher = mock<AuditPublisher>()
    private val gate = TrustedDeviceGate(mock<OidcClientRepository>(), mock<SamlSpRepository>(), devices, posture, auditPublisher)
    private val proofs = mock<DeviceLoginProofService>()
    private val service = DeviceLoginRuleService(rules, gate, auditPublisher, devices, proofs)

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
        service.set(tenantId, true, "admin-1", "test reason", "1.2.3.4")
        verify(rules).save(argThat<TenantDeviceLoginRuleEntity> { requireTrustedDevice && updatedBy == "admin-1" })
        verify(auditPublisher).publish(argThat<AuditEvent> { action == "tenant.device_login_rule.enabled" && reason == "test reason" })

        ruleOn()
        whenever(rules.existsById(tenantId)).thenReturn(true)
        service.set(tenantId, true, "admin-1", "test reason", "1.2.3.4")
        verify(auditPublisher, org.mockito.kotlin.times(1)).publish(any())
    }

    // ---- the early (email step) preview ----

    private val challengeId = UUID.randomUUID()

    private fun preview(proof: Boolean = true) = service.preview(
        LoginDevicePreviewRequest(tenantId, if (proof) challengeId else null, if (proof) deviceId else null, if (proof) "sig" else null, if (proof) "https://login.example.com" else null),
    )

    private fun proofAccepted() {
        whenever(proofs.verify(org.mockito.kotlin.eq(challengeId), any(), org.mockito.kotlin.anyOrNull()))
            .thenReturn(DeviceChallengeVerifyResponse(deviceId, "SOFTWARE"))
    }

    @Test
    fun `preview says nothing should be shown when the tenant rule is off`() {
        ruleOn(false)
        val answer = preview(proof = false)
        assertFalse(answer.ruleOn)
        assertTrue(answer.authorised)
        verify(devices, never()).findById(any())
    }

    @Test
    fun `preview with no proof at all is DEVICE_REQUIRED, and the email never takes part`() {
        ruleOn()
        val answer = preview(proof = false)
        assertTrue(answer.ruleOn)
        assertFalse(answer.authorised)
        assertEquals("DEVICE_REQUIRED", answer.code)
    }

    @Test
    fun `preview with a proof the platform rejects is DEVICE_REQUIRED`() {
        ruleOn(); device(); posture("COMPLIANT")
        whenever(proofs.verify(any(), any(), org.mockito.kotlin.anyOrNull())).thenThrow(DeviceProofOfPossessionException("rejected"))
        assertEquals("DEVICE_REQUIRED", preview().code)
    }

    @Test
    fun `preview with a claimed device in another tenant is DEVICE_REQUIRED and never reaches proof verification`() {
        ruleOn()
        whenever(devices.findById(deviceId)).thenReturn(
            Optional.of(IamDeviceEntity(deviceId, UUID.randomUUID(), userId, UUID.randomUUID(), ownership = "BYOD", lifecycleStatus = "APPROVED")),
        )
        assertEquals("DEVICE_REQUIRED", preview().code)
        verify(proofs, never()).verify(any(), any(), org.mockito.kotlin.anyOrNull())
    }

    @Test
    fun `preview accepts a proven, approved, compliant laptop`() {
        ruleOn(); device(); posture("COMPLIANT"); proofAccepted()
        val answer = preview()
        assertTrue(answer.ruleOn)
        assertTrue(answer.authorised)
        assertNull(answer.code)
    }

    @Test
    fun `preview refuses a proven laptop that is not approved or not compliant, with the reason`() {
        ruleOn(); proofAccepted()
        device(status = "PENDING_APPROVAL"); posture("COMPLIANT")
        assertEquals("DEVICE_NOT_APPROVED", preview().code)
        device(); posture("NON_COMPLIANT")
        assertEquals("DEVICE_NON_COMPLIANT", preview().code)
    }

    @Test
    fun `preview honours an active compliance exception but does not audit it, because it is not a sign-in`() {
        ruleOn(); proofAccepted()
        device(exceptionUntil = Instant.now().plusSeconds(3600)); posture("NON_COMPLIANT")
        assertTrue(preview().authorised)
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `an unknown tenant reads as off`() {
        assertFalse(service.isRequired(UUID.randomUUID()))
    }
}
