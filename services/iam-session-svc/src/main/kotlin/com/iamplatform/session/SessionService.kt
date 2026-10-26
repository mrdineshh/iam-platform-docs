package com.iamplatform.session

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Service
import tools.jackson.databind.ObjectMapper
import java.time.Instant
import java.util.UUID

@Service
class SessionService(
    private val redis: StringRedisTemplate,
    private val objectMapper: ObjectMapper,
    private val auditPublisher: AuditPublisher,
    private val properties: SessionProperties,
) {

    fun issue(request: IssueSessionRequest, idempotencyKey: String?): IssueResult {
        val token = SessionTokens.generate()

        if (idempotencyKey != null) {
            val idemKey = idempotencyKey(request.tenantId, idempotencyKey)
            // Claim the key atomically before issuing, so two concurrent retries
            // can't both pass the "not seen yet" check and issue two sessions.
            val claimed = redis.opsForValue().setIfAbsent(idemKey, token, properties.idempotencyWindow) == true
            if (!claimed) {
                return replay(idemKey, request)
            }
        }

        val now = Instant.now()
        val session = SessionRecord(
            sessionId = UUID.randomUUID(),
            tenantId = request.tenantId,
            userId = request.userId,
            sourceIp = request.sourceIp,
            deviceId = request.deviceId,
            issuedAt = now,
            expiresAt = now.plus(properties.ttl),
        )
        redis.opsForValue().set(sessionKey(token), objectMapper.writeValueAsString(session), properties.ttl)

        publish("session.issued", session, reason = "sessionId=${session.sessionId}")
        return IssueResult(token, session, replayed = false)
    }

    fun find(token: String): SessionRecord? =
        redis.opsForValue().get(sessionKey(token))?.let { objectMapper.readValue(it, SessionRecord::class.java) }

    fun terminate(token: String, reason: String?) {
        // GETDEL is atomic: two concurrent terminations can't both succeed and
        // double-publish session.terminated.
        val raw = redis.opsForValue().getAndDelete(sessionKey(token)) ?: throw SessionNotFoundException()
        val session = objectMapper.readValue(raw, SessionRecord::class.java)
        val detail = reason?.takeIf { it.isNotBlank() } ?: "unspecified"
        publish("session.terminated", session, reason = "sessionId=${session.sessionId}; $detail")
    }

    private fun replay(idemKey: String, request: IssueSessionRequest): IssueResult {
        val originalToken = redis.opsForValue().get(idemKey)
            ?: throw IdempotencyConflictException("Idempotency-Key is being processed or has expired; retry")
        val original = find(originalToken)
            ?: throw IdempotencyConflictException("Idempotency-Key refers to a session that no longer exists")
        if (original.tenantId != request.tenantId || original.userId != request.userId) {
            throw IdempotencyConflictException("Idempotency-Key was already used with a different request")
        }
        return IssueResult(originalToken, original, replayed = true)
    }

    private fun publish(action: String, session: SessionRecord, reason: String) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = session.tenantId,
                actorType = ActorType.USER,
                actorId = session.userId.toString(),
                action = action,
                result = AuditResult.SUCCESS,
                reason = reason,
                sourceIp = session.sourceIp,
                deviceId = session.deviceId,
            ),
        )
    }

    companion object {
        fun sessionKey(token: String): String = "session:${SessionTokens.hash(token)}"
        fun idempotencyKey(tenantId: UUID, key: String): String = "session-idem:$tenantId:$key"
    }
}
