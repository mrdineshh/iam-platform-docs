package com.iamplatform.session

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.data.redis.core.ValueOperations
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.time.Duration
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SessionServiceTest {

    private val ops = mock<ValueOperations<String, String>>()
    private val redis = mock<StringRedisTemplate>().also { whenever(it.opsForValue()).thenReturn(ops) }
    private val objectMapper = jacksonObjectMapper()
    private val auditPublisher = mock<AuditPublisher>()
    private val properties = SessionProperties()
    private val service = SessionService(redis, objectMapper, auditPublisher, properties)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()

    private fun storedSession(tenant: UUID = tenantId, user: UUID = userId): SessionRecord {
        val now = Instant.now()
        return SessionRecord(UUID.randomUUID(), tenant, user, "8.8.8.8", null, now, now.plus(Duration.ofHours(8)))
    }

    @Test
    fun `issue stores the session under the token hash with the configured TTL and publishes session-issued`() {
        val result = service.issue(IssueSessionRequest(tenantId, userId, sourceIp = "8.8.8.8"), idempotencyKey = null)

        assertFalse(result.replayed)
        verify(ops).set(eq(SessionService.sessionKey(result.token)), any(), eq(Duration.ofHours(8)))
        verify(ops, never()).set(eq("session:${result.token}"), any(), any<Duration>())

        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("session.issued", captor.firstValue.action)
        assertEquals(userId.toString(), captor.firstValue.actorId)
        assertEquals("8.8.8.8", captor.firstValue.sourceIp)
    }

    @Test
    fun `issue with a fresh idempotency key claims it before issuing`() {
        whenever(ops.setIfAbsent(any(), any(), any<Duration>())).thenReturn(true)

        val result = service.issue(IssueSessionRequest(tenantId, userId), idempotencyKey = "retry-1")

        assertFalse(result.replayed)
        verify(ops).setIfAbsent(eq(SessionService.idempotencyKey(tenantId, "retry-1")), eq(result.token), eq(Duration.ofMinutes(10)))
        verify(auditPublisher).publish(any())
    }

    @Test
    fun `issue replaying an idempotency key returns the original session without issuing or auditing again`() {
        val original = storedSession()
        whenever(ops.setIfAbsent(any(), any(), any<Duration>())).thenReturn(false)
        whenever(ops.get(SessionService.idempotencyKey(tenantId, "retry-1"))).thenReturn("original-token")
        whenever(ops.get(SessionService.sessionKey("original-token"))).thenReturn(objectMapper.writeValueAsString(original))

        val result = service.issue(IssueSessionRequest(tenantId, userId), idempotencyKey = "retry-1")

        assertTrue(result.replayed)
        assertEquals("original-token", result.token)
        assertEquals(original.sessionId, result.session.sessionId)
        verify(ops, never()).set(any(), any(), any<Duration>())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `replaying an idempotency key with a different user is a conflict`() {
        val original = storedSession(user = UUID.randomUUID())
        whenever(ops.setIfAbsent(any(), any(), any<Duration>())).thenReturn(false)
        whenever(ops.get(SessionService.idempotencyKey(tenantId, "retry-1"))).thenReturn("original-token")
        whenever(ops.get(SessionService.sessionKey("original-token"))).thenReturn(objectMapper.writeValueAsString(original))

        assertThrows<IdempotencyConflictException> {
            service.issue(IssueSessionRequest(tenantId, userId), idempotencyKey = "retry-1")
        }
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `replaying an idempotency key whose session was terminated is a conflict`() {
        whenever(ops.setIfAbsent(any(), any(), any<Duration>())).thenReturn(false)
        whenever(ops.get(SessionService.idempotencyKey(tenantId, "retry-1"))).thenReturn("original-token")
        whenever(ops.get(SessionService.sessionKey("original-token"))).thenReturn(null)

        assertThrows<IdempotencyConflictException> {
            service.issue(IssueSessionRequest(tenantId, userId), idempotencyKey = "retry-1")
        }
    }

    @Test
    fun `find returns the stored session, or null for an unknown token`() {
        val session = storedSession()
        whenever(ops.get(SessionService.sessionKey("known"))).thenReturn(objectMapper.writeValueAsString(session))

        assertEquals(session, service.find("known"))
        assertNull(service.find("unknown"))
    }

    @Test
    fun `terminate atomically deletes and publishes session-terminated with the reason`() {
        val session = storedSession()
        whenever(ops.getAndDelete(SessionService.sessionKey("tok"))).thenReturn(objectMapper.writeValueAsString(session))

        service.terminate("tok", reason = "policy violation: country KP")

        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("session.terminated", captor.firstValue.action)
        assertEquals("sessionId=${session.sessionId}; policy violation: country KP", captor.firstValue.reason)
    }

    @Test
    fun `terminating an unknown session throws and publishes nothing`() {
        whenever(ops.getAndDelete(any())).thenReturn(null)

        assertThrows<SessionNotFoundException> { service.terminate("gone", reason = null) }
        verify(auditPublisher, never()).publish(any())
    }
}
