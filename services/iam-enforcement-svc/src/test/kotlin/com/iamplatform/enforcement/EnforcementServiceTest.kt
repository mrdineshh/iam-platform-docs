package com.iamplatform.enforcement

import com.iamplatform.enforcement.client.EvaluateResponse
import com.iamplatform.enforcement.client.GeoClient
import com.iamplatform.enforcement.client.GeoResolution
import com.iamplatform.enforcement.client.PolicyClient
import com.iamplatform.enforcement.client.RemoteSession
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
    private val policyCache = mock<PolicyDecisionCache>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = EnforcementService(sessionClient, geoClient, policyClient, policyCache, auditPublisher)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val session = RemoteSession(
        sessionId = UUID.randomUUID(), tenantId = tenantId, userId = userId,
        sourceIp = "8.8.8.8", issuedAt = Instant.now(), expiresAt = Instant.now().plusSeconds(3600),
    )

    @Test
    fun `unknown session is denied without touching geo, policy, or audit`() {
        whenever(sessionClient.validate("bad-token")).thenReturn(null)

        assertThrows<EnforcementDeniedException> { service.enforce("bad-token", EnforceRequest("8.8.8.8")) }

        verify(geoClient, never()).resolve(any())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `unresolved location is denied and audited, but the session is not terminated`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        whenever(geoClient.resolve("1.2.3.4")).thenReturn(GeoResolution("1.2.3.4", resolved = false))

        val ex = assertThrows<EnforcementDeniedException> { service.enforce("tok", EnforceRequest("1.2.3.4")) }

        assertEquals("location could not be verified", ex.message)
        verify(sessionClient, never()).terminate(any(), any())
        verify(auditPublisher).publish(any<AuditEvent>())
    }

    @Test
    fun `policy-svc unreachable is denied and audited, but the session is not terminated`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyCache.get(tenantId, userId, "US")).thenReturn(null)
        whenever(policyClient.evaluate(tenantId, userId, "US")).thenThrow(
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
        whenever(geoClient.resolve("1.2.3.4")).thenReturn(GeoResolution("1.2.3.4", resolved = true, country = "KP"))
        whenever(policyCache.get(tenantId, userId, "KP")).thenReturn(null)
        whenever(policyClient.evaluate(tenantId, userId, "KP"))
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
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyCache.get(tenantId, userId, "US")).thenReturn(null)
        whenever(policyClient.evaluate(tenantId, userId, "US")).thenReturn(EvaluateResponse(allowed = true))

        val result = service.enforce("tok", EnforceRequest("8.8.8.8"))

        assertTrue(result.allowed)
        assertEquals("US", result.country)
        verify(sessionClient, never()).terminate(any(), any())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `a cached policy decision skips calling policy-svc again`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyCache.get(tenantId, userId, "US")).thenReturn(EvaluateResponse(allowed = true))

        service.enforce("tok", EnforceRequest("8.8.8.8"))

        verify(policyClient, never()).evaluate(any(), any(), any())
    }

    @Test
    fun `a fresh policy evaluation is cached for next time`() {
        whenever(sessionClient.validate("tok")).thenReturn(session)
        whenever(geoClient.resolve("8.8.8.8")).thenReturn(GeoResolution("8.8.8.8", resolved = true, country = "US"))
        whenever(policyCache.get(tenantId, userId, "US")).thenReturn(null)
        val evaluated = EvaluateResponse(allowed = true)
        whenever(policyClient.evaluate(tenantId, userId, "US")).thenReturn(evaluated)

        service.enforce("tok", EnforceRequest("8.8.8.8"))

        verify(policyCache).put(tenantId, userId, "US", evaluated)
    }
}
