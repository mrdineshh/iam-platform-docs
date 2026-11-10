package com.iamplatform.enforcement

import com.iamplatform.enforcement.client.DeviceTrustClient
import com.iamplatform.enforcement.client.EvaluateResponse
import com.iamplatform.enforcement.client.GeoClient
import com.iamplatform.enforcement.client.GeoResolution
import com.iamplatform.enforcement.client.IdentityClient
import com.iamplatform.enforcement.client.PolicyClient
import com.iamplatform.enforcement.client.RemoteDeviceTrustStatus
import com.iamplatform.enforcement.client.RemoteSession
import com.iamplatform.enforcement.client.RemoteUser
import com.iamplatform.enforcement.client.RemoteUserStatus
import com.iamplatform.enforcement.client.SessionClient
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import io.github.resilience4j.circuitbreaker.CallNotPermittedException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EnforcementServiceTest {

    private val sessionClient = mock<SessionClient>()
    private val geoClient = mock<GeoClient>()
    private val policyClient = mock<PolicyClient>()
    private val identityClient = mock<IdentityClient>()
    private val deviceTrustClient = mock<DeviceTrustClient>()
    private val policyCache = mock<PolicyDecisionCache>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = EnforcementService(sessionClient, geoClient, policyClient, identityClient, deviceTrustClient, policyCache, auditPublisher)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val session = RemoteSession(
        sessionId = UUID.randomUUID(), tenantId = tenantId, userId = userId,
        sourceIp = "8.8.8.8", issuedAt = Instant.now(), expiresAt = Instant.now().plusSeconds(3600),
    )

    private fun stubActiveUser() {
        whenever(identityClient.findUser(userId)).thenReturn(RemoteUser(userId, tenantId, RemoteUserStatus.ACTIVE))
    }

    @Test
    fun `unknown session is denied without touching geo, policy, or audit`() {
        whenever(sessionClient.validate("bad-token")).thenReturn(null)

        assertThrows<EnforcementDeniedException> { service.enforce("bad-token", EnforceRequest("8.8.8.8")) }

        verify(geoClient, never()).resolve(any())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `a deleted or suspended user terminates the session`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        whenever(identityClient.findUser(userId)).thenReturn(null)

        val ex = assertThrows<EnforcementDeniedException> { service.enforce("tok", EnforceRequest("8.8.8.8")) }

        assertEquals("user no longer exists or is suspended", ex.message)
        verify(sessionClient).terminate("tok", "user no longer exists or is suspended")
        verify(geoClient, never()).resolve(any())
    }

    @Test
    fun `unresolved location is denied and audited, but the session is not terminated`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        stubActiveUser()
        whenever(geoClient.resolve("1.2.3.4")).thenReturn(GeoResolution("1.2.3.4", resolved = false))

        val ex = assertThrows<EnforcementDeniedException> { service.enforce("tok", EnforceRequest("1.2.3.4")) }

        assertEquals("location could not be verified", ex.message)
        verify(sessionClient, never()).terminate(any(), any())
        verify(auditPublisher).publish(any<AuditEvent>())
    }

    @Test
    fun `policy-svc unreachable is denied and audited, but the session is not terminated`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        stubActiveUser()
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyCache.get(tenantId, userId, "US")).thenReturn(null)
        whenever(policyClient.evaluate(tenantId, userId, "US", "8.8.8.8")).thenThrow(
            CallNotPermittedException.createCallNotPermittedException(
                io.github.resilience4j.circuitbreaker.CircuitBreaker.ofDefaults("policy-svc"),
            ),
        )

        val ex = assertThrows<EnforcementDeniedException> { service.enforce("tok", EnforceRequest("8.8.8.8")) }

        assertEquals("policy could not be evaluated", ex.message)
        verify(sessionClient, never()).terminate(any(), any())
    }

    @Test
    fun `a confirmed policy violation terminates the session and is audited as enforcement-violation`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        stubActiveUser()
        whenever(geoClient.resolve("1.2.3.4")).thenReturn(GeoResolution("1.2.3.4", resolved = true, country = "KP"))
        whenever(policyCache.get(tenantId, userId, "KP")).thenReturn(null)
        whenever(policyClient.evaluate(tenantId, userId, "KP", "1.2.3.4"))
            .thenReturn(EvaluateResponse(allowed = false, reason = "country 'KP' is in blockedCountries", policyScopeApplied = "TENANT"))

        val ex = assertThrows<EnforcementDeniedException> { service.enforce("tok", EnforceRequest("1.2.3.4")) }

        assertEquals("country 'KP' is in blockedCountries", ex.message)
        verify(sessionClient).terminate("tok", "country 'KP' is in blockedCountries")
        val captor = org.mockito.kotlin.argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("enforcement.violation", captor.firstValue.action)
    }

    @Test
    fun `an allowed check returns 200-shaped data, terminates nothing, and publishes no audit event`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        stubActiveUser()
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyCache.get(tenantId, userId, "US")).thenReturn(null)
        whenever(policyClient.evaluate(tenantId, userId, "US", "8.8.8.8")).thenReturn(EvaluateResponse(allowed = true))

        val result = service.enforce("tok", EnforceRequest("8.8.8.8"))

        assertTrue(result.allowed)
        assertEquals("US", result.country)
        verify(sessionClient, never()).terminate(any(), any())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `a cached policy decision skips calling policy-svc again`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        stubActiveUser()
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyCache.get(tenantId, userId, "US")).thenReturn(EvaluateResponse(allowed = true))

        service.enforce("tok", EnforceRequest("8.8.8.8"))

        verify(policyClient, never()).evaluate(any(), any(), any(), any())
    }

    @Test
    fun `a fresh policy evaluation is cached for next time`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        stubActiveUser()
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyCache.get(tenantId, userId, "US")).thenReturn(null)
        val evaluated = EvaluateResponse(allowed = true)
        whenever(policyClient.evaluate(tenantId, userId, "US", "8.8.8.8")).thenReturn(evaluated)

        service.enforce("tok", EnforceRequest("8.8.8.8"))

        verify(policyCache).put(tenantId, userId, "US", evaluated)
    }

    // ---- Device trust (Endpoint Device Trust spec Section 4.2) ----

    @Test
    fun `a session with no deviceId claim skips the device-trust check entirely`() {
        whenever(sessionClient.validate("tok")).thenReturn(session) // deviceId is null
        stubActiveUser()
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyCache.get(tenantId, userId, "US")).thenReturn(EvaluateResponse(allowed = true))

        service.enforce("tok", EnforceRequest("8.8.8.8"))

        verify(deviceTrustClient, never()).findDeviceTrustStatus(any(), any())
    }

    @Test
    fun `an approved claimed device passes through to the normal policy check`() {
        val deviceId = UUID.randomUUID()
        val deviceSession = session.copy(deviceId = deviceId.toString())
        whenever(sessionClient.validate("tok")).thenReturn(deviceSession)
        stubActiveUser()
        whenever(deviceTrustClient.findDeviceTrustStatus(tenantId, deviceId))
            .thenReturn(RemoteDeviceTrustStatus(deviceId, tenantId, "APPROVED"))
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyCache.get(tenantId, userId, "US")).thenReturn(EvaluateResponse(allowed = true))

        val result = service.enforce("tok", EnforceRequest("8.8.8.8"))

        assertTrue(result.allowed)
        verify(sessionClient, never()).terminate(any(), any())
    }

    @Test
    fun `a revoked claimed device terminates the session before any geo or policy check`() {
        val deviceId = UUID.randomUUID()
        val deviceSession = session.copy(deviceId = deviceId.toString())
        whenever(sessionClient.validate("tok")).thenReturn(deviceSession)
        stubActiveUser()
        whenever(deviceTrustClient.findDeviceTrustStatus(tenantId, deviceId))
            .thenReturn(RemoteDeviceTrustStatus(deviceId, tenantId, "REVOKED"))

        val ex = assertThrows<EnforcementDeniedException> { service.enforce("tok", EnforceRequest("8.8.8.8")) }

        assertEquals("device is revoked, not approved", ex.message)
        verify(sessionClient).terminate("tok", "device is revoked, not approved")
        verify(geoClient, never()).resolve(any())
    }

    @Test
    fun `a claimed device that no longer exists terminates the session`() {
        val deviceId = UUID.randomUUID()
        val deviceSession = session.copy(deviceId = deviceId.toString())
        whenever(sessionClient.validate("tok")).thenReturn(deviceSession)
        stubActiveUser()
        whenever(deviceTrustClient.findDeviceTrustStatus(tenantId, deviceId)).thenReturn(null)

        val ex = assertThrows<EnforcementDeniedException> { service.enforce("tok", EnforceRequest("8.8.8.8")) }

        assertEquals("device is no longer registered", ex.message)
        verify(sessionClient).terminate("tok", "device is no longer registered")
    }
}
