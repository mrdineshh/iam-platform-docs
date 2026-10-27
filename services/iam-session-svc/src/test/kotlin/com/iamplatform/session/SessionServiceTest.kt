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
import org.springframework.data.redis.core.SetOperations
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
    private val setOps = mock<SetOperations<String, String>>()
    private val redis = mock<StringRedisTemplate>().also {
        whenever(it.opsForValue()).thenReturn(ops)
        whenever(it.opsForSet()).thenReturn(setOps)
    }
    private val objectMapper = jacksonObjectMapper()
    private val auditPublisher = mock<AuditPublisher>()
    private val properties = SessionProperties(ttl = Duration.ofHours(8)) // application.yml sets 8h; the class default is 1h
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

    @Test
    fun `issue indexes the token hash under the user so sessions can be listed`() {
        val result = service.issue(IssueSessionRequest(tenantId, userId), idempotencyKey = null)

        verify(setOps).add(eq(SessionService.userIndexKey(tenantId, userId)), eq(SessionTokens.hash(result.token)))
        verify(redis).expire(eq(SessionService.userIndexKey(tenantId, userId)), eq(Duration.ofHours(8)))
    }

    @Test
    fun `terminate also removes the session from the user index`() {
        val session = storedSession()
        whenever(ops.getAndDelete(SessionService.sessionKey("tok"))).thenReturn(objectMapper.writeValueAsString(session))

        service.terminate("tok", reason = null)

        verify(setOps).remove(eq(SessionService.userIndexKey(tenantId, userId)), eq(SessionTokens.hash("tok")))
    }

    @Test
    fun `listForUser returns live sessions newest first and prunes dead index entries`() {
        val indexKey = SessionService.userIndexKey(tenantId, userId)
        val now = Instant.now()
        val older = storedSession().copy(issuedAt = now.minusSeconds(600))
        val newer = storedSession().copy(issuedAt = now)
        whenever(setOps.members(indexKey)).thenReturn(setOf("h1", "h2", "h3"))
        whenever(ops.get(SessionService.sessionKeyForHash("h1"))).thenReturn(objectMapper.writeValueAsString(older))
        whenever(ops.get(SessionService.sessionKeyForHash("h2"))).thenReturn(objectMapper.writeValueAsString(newer))
        whenever(ops.get(SessionService.sessionKeyForHash("h3"))).thenReturn(null)

        val result = service.listForUser(tenantId, userId)

        assertEquals(listOf(newer.sessionId, older.sessionId), result.map { it.sessionId })
        verify(setOps).remove(eq(indexKey), eq("h3"))
    }

    @Test
    fun `listForUser never returns a session that belongs to a different user`() {
        val indexKey = SessionService.userIndexKey(tenantId, userId)
        val foreign = storedSession(user = UUID.randomUUID())
        whenever(setOps.members(indexKey)).thenReturn(setOf("h1"))
        whenever(ops.get(SessionService.sessionKeyForHash("h1"))).thenReturn(objectMapper.writeValueAsString(foreign))

        assertTrue(service.listForUser(tenantId, userId).isEmpty())
    }

    @Test
    fun `terminateAllForUser ends every live session and audits each one`() {
        val indexKey = SessionService.userIndexKey(tenantId, userId)
        whenever(setOps.members(indexKey)).thenReturn(setOf("h1", "h2", "h3"))
        whenever(ops.getAndDelete(SessionService.sessionKeyForHash("h1"))).thenReturn(objectMapper.writeValueAsString(storedSession()))
        whenever(ops.getAndDelete(SessionService.sessionKeyForHash("h2"))).thenReturn(objectMapper.writeValueAsString(storedSession()))
        whenever(ops.getAndDelete(SessionService.sessionKeyForHash("h3"))).thenReturn(null)

        val ended = service.terminateAllForUser(tenantId, userId, reason = "revoked by admin")

        assertEquals(2, ended)
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher, org.mockito.kotlin.times(2)).publish(captor.capture())
        assertTrue(captor.allValues.all { it.action == "session.terminated" && it.reason!!.endsWith("revoked by admin") })
    }

    @Test
    fun `terminateOneForUser ends only the matching session`() {
        val indexKey = SessionService.userIndexKey(tenantId, userId)
        val other = storedSession()
        val target = storedSession()
        whenever(setOps.members(indexKey)).thenReturn(setOf("h1", "h2"))
        whenever(ops.get(SessionService.sessionKeyForHash("h1"))).thenReturn(objectMapper.writeValueAsString(other))
        whenever(ops.get(SessionService.sessionKeyForHash("h2"))).thenReturn(objectMapper.writeValueAsString(target))
        whenever(ops.getAndDelete(SessionService.sessionKeyForHash("h2"))).thenReturn(objectMapper.writeValueAsString(target))

        service.terminateOneForUser(tenantId, userId, target.sessionId, reason = null)

        verify(ops).getAndDelete(SessionService.sessionKeyForHash("h2"))
        verify(ops, never()).getAndDelete(SessionService.sessionKeyForHash("h1"))
        verify(auditPublisher).publish(any())
    }

    @Test
    fun `terminateOneForUser with an unknown sessionId throws and audits nothing`() {
        val indexKey = SessionService.userIndexKey(tenantId, userId)
        whenever(setOps.members(indexKey)).thenReturn(setOf("h1"))
        whenever(ops.get(SessionService.sessionKeyForHash("h1"))).thenReturn(objectMapper.writeValueAsString(storedSession()))

        assertThrows<SessionNotFoundException> {
            service.terminateOneForUser(tenantId, userId, UUID.randomUUID(), reason = null)
        }
        verify(auditPublisher, never()).publish(any())
    }
}
