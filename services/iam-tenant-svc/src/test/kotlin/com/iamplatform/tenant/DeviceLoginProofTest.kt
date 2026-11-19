package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.argThat
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.security.KeyPairGenerator
import java.security.Signature
import java.time.Instant
import java.util.Base64
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DeviceLoginProofTest {

    private val challenges = mock<DeviceLoginChallengeRepository>()
    private val devices = mock<IamDeviceRepository>()
    private val keys = mock<DeviceKeyRepository>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = DeviceLoginProofService(challenges, devices, keys, DeviceSignatureVerifier(), auditPublisher)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val deviceId = UUID.randomUUID()
    private val origin = "https://login.example.com"
    private val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()

    private lateinit var challenge: DeviceLoginChallengeEntity

    @BeforeEach
    fun setUp() {
        challenge = DeviceLoginChallengeEntity(UUID.randomUUID(), tenantId, "nonce-123", Instant.now().plusSeconds(60))
        whenever(challenges.findById(challenge.id)).thenAnswer { Optional.of(challenge) }
        whenever(challenges.consume(eq(challenge.id), any())).thenReturn(1)
        whenever(challenges.save(any<DeviceLoginChallengeEntity>())).thenAnswer { it.arguments[0] }
        whenever(devices.findById(deviceId)).thenReturn(Optional.of(device()))
        whenever(keys.findByDeviceIdAndStatus(deviceId, KeyStatus.ACTIVE.name)).thenReturn(
            DeviceKeyEntity(UUID.randomUUID(), deviceId, Base64.getEncoder().encodeToString(keyPair.public.encoded), "ED25519", "SOFTWARE"),
        )
    }

    private fun device(owner: UUID = userId, tenant: UUID = tenantId, status: String = DeviceLifecycleStatus.APPROVED.name) =
        IamDeviceEntity(deviceId, tenant, owner, UUID.randomUUID(), ownership = "BYOD", lifecycleStatus = status)

    private fun signed(payloadOrigin: String = origin, c: DeviceLoginChallengeEntity = challenge): String {
        val payload = DeviceLoginProofService.canonicalPayload(c, deviceId, payloadOrigin).toByteArray(Charsets.UTF_8)
        val sig = Signature.getInstance("Ed25519").apply { initSign(keyPair.private); update(payload) }.sign()
        return Base64.getEncoder().encodeToString(sig)
    }

    private fun request(signature: String = signed(), requestOrigin: String = origin, user: UUID = userId) =
        DeviceChallengeVerifyRequest(user, deviceId, signature, requestOrigin)

    @Test
    fun `issue creates a one-minute single-use challenge with a random nonce`() {
        val a = service.issue(tenantId)
        val b = service.issue(tenantId)
        assertTrue(a.nonce.length >= 40)
        assertTrue(a.nonce != b.nonce)
        assertTrue(a.expiresAt.isBefore(Instant.now().plusSeconds(121)))
        assertTrue(a.expiresAt.isAfter(Instant.now().plusSeconds(100)))
    }

    @Test
    fun `issuing a challenge also clears long-expired ones so the table cannot grow without bound`() {
        service.issue(tenantId)
        verify(challenges).deleteExpiredBefore(any())
    }

    @Test
    fun `a proper proof from the owner's laptop is accepted and reports the key's assurance level`() {
        val result = service.verify(challenge.id, request(), "1.2.3.4")
        assertEquals(deviceId, result.deviceId)
        assertEquals("SOFTWARE", result.assuranceLevel)
        val event = argumentCaptor<AuditEvent>().also { verify(auditPublisher).publish(it.capture()) }.firstValue
        assertEquals("device.login_proof.accepted", event.action)
    }

    @Test
    fun `a challenge can be used only once`() {
        whenever(challenges.consume(eq(challenge.id), any())).thenReturn(1, 0)
        service.verify(challenge.id, request(), null)
        assertThrows<DeviceProofOfPossessionException> { service.verify(challenge.id, request(), null) }
    }

    @Test
    fun `a failed attempt still burns the challenge so it cannot be retried`() {
        assertThrows<DeviceProofOfPossessionException> { service.verify(challenge.id, request(signature = "AAAA"), null) }
        verify(challenges).consume(eq(challenge.id), any())
    }

    @Test
    fun `an expired challenge is refused`() {
        challenge.expiresAt = Instant.now().minusSeconds(1)
        assertThrows<DeviceProofOfPossessionException> { service.verify(challenge.id, request(), null) }
    }

    @Test
    fun `an unknown challenge is refused`() {
        assertThrows<DeviceProofOfPossessionException> { service.verify(UUID.randomUUID(), request(), null) }
    }

    @Test
    fun `a laptop enrolled by a different user cannot vouch for this sign-in`() {
        whenever(devices.findById(deviceId)).thenReturn(Optional.of(device(owner = UUID.randomUUID())))
        assertThrows<DeviceProofOfPossessionException> { service.verify(challenge.id, request(), null) }
    }

    @Test
    fun `the same laptop and valid signature are refused when the authenticated user is someone else`() {
        // The signature is perfect and the laptop exists, but auth-svc authenticated a different person.
        assertThrows<DeviceProofOfPossessionException> { service.verify(challenge.id, request(user = UUID.randomUUID()), null) }
    }

    @Test
    fun `a laptop from another tenant is refused`() {
        whenever(devices.findById(deviceId)).thenReturn(Optional.of(device(tenant = UUID.randomUUID())))
        assertThrows<DeviceProofOfPossessionException> { service.verify(challenge.id, request(), null) }
    }

    @Test
    fun `a revoked laptop is refused`() {
        whenever(devices.findById(deviceId)).thenReturn(Optional.of(device(status = "REVOKED")))
        assertThrows<DeviceProofOfPossessionException> { service.verify(challenge.id, request(), null) }
    }

    @Test
    fun `a signature made for a different origin does not verify`() {
        // The agent signed for evil.example, the platform is told the sign-in came from the real login page.
        assertThrows<DeviceProofOfPossessionException> { service.verify(challenge.id, request(signature = signed("https://evil.example")), null) }
    }

    @Test
    fun `a signature from a different key does not verify`() {
        val other = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val payload = DeviceLoginProofService.canonicalPayload(challenge, deviceId, origin).toByteArray(Charsets.UTF_8)
        val forged = Base64.getEncoder().encodeToString(Signature.getInstance("Ed25519").apply { initSign(other.private); update(payload) }.sign())
        assertThrows<DeviceProofOfPossessionException> { service.verify(challenge.id, request(signature = forged), null) }
    }

    @Test
    fun `a rejection is audited with the reason but the caller only sees a generic error`() {
        val ex = assertThrows<DeviceProofOfPossessionException> { service.verify(challenge.id, request(signature = "AAAA"), null) }
        assertEquals("Device proof rejected", ex.message)
        val event = argumentCaptor<AuditEvent>().also { verify(auditPublisher).publish(it.capture()) }.firstValue
        assertEquals("device.login_proof.rejected", event.action)
        assertNotNull(event.reason)
    }
}

class TrustedDeviceGateTest {

    private val oidcClients = mock<OidcClientRepository>()
    private val samlSps = mock<SamlSpRepository>()
    private val devices = mock<IamDeviceRepository>()
    private val posture = mock<DevicePostureRepository>()
    private val auditPublisher = mock<AuditPublisher>()
    private val gate = TrustedDeviceGate(oidcClients, samlSps, devices, posture, auditPublisher)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val appId = UUID.randomUUID()
    private val deviceId = UUID.randomUUID()

    private fun app(required: Boolean, allowPending: Boolean = false) {
        whenever(oidcClients.findById(appId)).thenReturn(
            Optional.of(OidcClientEntity(appId, tenantId, "App", "h", "https://a/cb", requireTrustedDevice = required, allowPendingDevice = allowPending)),
        )
    }

    @Test
    fun `a pending laptop is refused by default`() {
        app(true); device(status = "PENDING_APPROVAL"); posture("COMPLIANT")
        assertTrue(gate.check(tenantId, userId, "oidc", appId, deviceId.toString())!!.reason!!.contains("not approved"))
    }

    @Test
    fun `a pending laptop may open an app whose policy allows pending devices`() {
        app(true, allowPending = true); device(status = "PENDING_APPROVAL"); posture("COMPLIANT")
        assertNull(gate.check(tenantId, userId, "oidc", appId, deviceId.toString()))
    }

    @Test
    fun `allowing pending devices never lets a suspended, revoked or rejected laptop in`() {
        app(true, allowPending = true); posture("COMPLIANT")
        for (status in listOf("SUSPENDED", "REVOKED", "REJECTED", "DECOMMISSIONED")) {
            device(status = status)
            assertNotNull(gate.check(tenantId, userId, "oidc", appId, deviceId.toString()), status)
        }
    }

    @Test
    fun `a pending laptop that fails the security checks is still refused`() {
        app(true, allowPending = true); device(status = "PENDING_APPROVAL"); posture("NON_COMPLIANT")
        assertTrue(gate.check(tenantId, userId, "oidc", appId, deviceId.toString())!!.reason!!.contains("security requirements"))
    }

    @Test
    fun `the pending setting alone, without a trusted-device requirement, changes nothing`() {
        app(false, allowPending = true)
        assertNull(gate.check(tenantId, userId, "oidc", appId, null))
    }

    private fun device(status: String = "APPROVED", owner: UUID = userId, tenant: UUID = tenantId, exceptionUntil: java.time.Instant? = null) {
        whenever(devices.findById(deviceId)).thenReturn(
            Optional.of(
                IamDeviceEntity(deviceId, tenant, owner, UUID.randomUUID(), ownership = "BYOD", lifecycleStatus = status, complianceExceptionUntil = exceptionUntil),
            ),
        )
    }

    private val inAWeek get() = java.time.Instant.now().plusSeconds(7 * 86400)
    private val anHourAgo get() = java.time.Instant.now().minusSeconds(3600)

    @Test
    fun `an active compliance exception lets a non-compliant approved laptop in, and that use is audited`() {
        app(true); device(exceptionUntil = inAWeek); posture("NON_COMPLIANT")
        assertNull(gate.check(tenantId, userId, "oidc", appId, deviceId.toString()))
        verify(auditPublisher).publish(argThat<AuditEvent> { action == "app.access.allowed_compliance_exception" })
    }

    @Test
    fun `an active compliance exception also covers the NON_COMPLIANT lifecycle state`() {
        app(true); device(status = "NON_COMPLIANT", exceptionUntil = inAWeek); posture("NON_COMPLIANT")
        assertNull(gate.check(tenantId, userId, "oidc", appId, deviceId.toString()))
    }

    @Test
    fun `an expired compliance exception counts for nothing`() {
        app(true); device(exceptionUntil = anHourAgo); posture("NON_COMPLIANT")
        assertTrue(gate.check(tenantId, userId, "oidc", appId, deviceId.toString())!!.reason!!.contains("security requirements"))
    }

    @Test
    fun `a compliance exception never lets a pending, suspended, revoked or decommissioned laptop in`() {
        app(true); posture("NON_COMPLIANT")
        for (status in listOf("PENDING_APPROVAL", "SUSPENDED", "REVOKED", "REJECTED", "DECOMMISSIONED")) {
            device(status = status, exceptionUntil = inAWeek)
            assertNotNull(gate.check(tenantId, userId, "oidc", appId, deviceId.toString()), status)
        }
    }

    @Test
    fun `a compliance exception on someone else's laptop does not help`() {
        app(true); device(owner = UUID.randomUUID(), exceptionUntil = inAWeek); posture("NON_COMPLIANT")
        assertNotNull(gate.check(tenantId, userId, "oidc", appId, deviceId.toString()))
    }

    @Test
    fun `a compliant laptop with an exception is let in without an exception audit`() {
        app(true); device(exceptionUntil = inAWeek); posture("COMPLIANT")
        assertNull(gate.check(tenantId, userId, "oidc", appId, deviceId.toString()))
        verify(auditPublisher, never()).publish(any())
    }

    private fun posture(status: String) {
        whenever(posture.findById(deviceId)).thenReturn(Optional.of(DevicePostureEntity(deviceId, status)))
    }

    @Test
    fun `an app that does not require a trusted device is never touched`() {
        app(required = false)
        assertNull(gate.check(tenantId, userId, "oidc", appId, null))
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `a flagged app is allowed for an approved, compliant laptop of the same user`() {
        app(true); device(); posture("COMPLIANT")
        assertNull(gate.check(tenantId, userId, "oidc", appId, deviceId.toString()))
    }

    @Test
    fun `a flagged app is allowed when posture is only unknown`() {
        app(true); device(); posture("UNKNOWN")
        assertNull(gate.check(tenantId, userId, "oidc", appId, deviceId.toString()))
    }

    @Test
    fun `a flagged app refuses a sign-in with no device and says how to fix it`() {
        app(true)
        val denial = gate.check(tenantId, userId, "oidc", appId, null)
        assertNotNull(denial)
        assertEquals(false, denial.allowed)
        assertTrue(denial.reason!!.contains("Install the endpoint agent"))
    }

    @Test
    fun `a flagged app refuses a suspended laptop`() {
        app(true); device(status = "SUSPENDED"); posture("COMPLIANT")
        assertTrue(gate.check(tenantId, userId, "oidc", appId, deviceId.toString())!!.reason!!.contains("not approved"))
    }

    @Test
    fun `a flagged app refuses a non-compliant laptop`() {
        app(true); device(); posture("NON_COMPLIANT")
        assertTrue(gate.check(tenantId, userId, "oidc", appId, deviceId.toString())!!.reason!!.contains("security requirements"))
    }

    @Test
    fun `a flagged app refuses someone else's laptop even if the session names it`() {
        app(true); device(owner = UUID.randomUUID()); posture("COMPLIANT")
        assertNotNull(gate.check(tenantId, userId, "oidc", appId, deviceId.toString()))
    }

    @Test
    fun `a garbage device id on the session counts as no device`() {
        app(true)
        assertNotNull(gate.check(tenantId, userId, "oidc", appId, "not-a-uuid"))
    }

    @Test
    fun `a denial is audited`() {
        app(true)
        gate.check(tenantId, userId, "oidc", appId, null)
        val event = argumentCaptor<AuditEvent>().also { verify(auditPublisher).publish(it.capture()) }.firstValue
        assertEquals("app.access.denied_untrusted_device", event.action)
    }
}

class TrustedDeviceRequirementServiceTest {

    private val oidc = mock<OidcClientRepository>()
    private val saml = mock<SamlSpRepository>()
    private val service = TrustedDeviceRequirementService(oidc, saml)
    private val tenantId = UUID.randomUUID()

    @Test
    fun `a tenant with no flagged app does not require anything`() {
        assertEquals(false, service.tenantRequires(tenantId))
    }

    @Test
    fun `a flagged OIDC app or a flagged SAML app each make the tenant require it`() {
        whenever(oidc.existsByTenantIdAndRequireTrustedDeviceTrue(tenantId)).thenReturn(true)
        assertEquals(true, service.tenantRequires(tenantId))
        whenever(oidc.existsByTenantIdAndRequireTrustedDeviceTrue(tenantId)).thenReturn(false)
        whenever(saml.existsByTenantIdAndRequireTrustedDeviceTrue(tenantId)).thenReturn(true)
        assertEquals(true, service.tenantRequires(tenantId))
    }

    @Test
    fun `another tenant's flagged app does not count`() {
        whenever(oidc.existsByTenantIdAndRequireTrustedDeviceTrue(UUID.randomUUID())).thenReturn(true)
        assertEquals(false, service.tenantRequires(tenantId))
    }
}
