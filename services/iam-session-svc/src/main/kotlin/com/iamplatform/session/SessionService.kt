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

        // Per-user index of token hashes (never raw tokens) so an admin or the
        // user can list and revoke their sessions. Its TTL is refreshed on every
        // issue, so it outlives the newest member and then disappears on its own.
        val indexKey = userIndexKey(session.tenantId, session.userId)
        redis.opsForSet().add(indexKey, SessionTokens.hash(token))
        redis.expire(indexKey, properties.ttl)

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
        redis.opsForSet().remove(userIndexKey(session.tenantId, session.userId), SessionTokens.hash(token))
        publishTerminated(session, reason)
    }

    /**
     * Live sessions for one user, newest first. Index entries whose session has
     * already expired or been terminated are pruned as they are found. Sessions
     * issued before this index existed are not listed; they expire on their own.
     */
    fun listForUser(tenantId: UUID, userId: UUID): List<SessionRecord> {
        val indexKey = userIndexKey(tenantId, userId)
        val sessions = mutableListOf<SessionRecord>()
        for (hash in redis.opsForSet().members(indexKey).orEmpty()) {
            val raw = redis.opsForValue().get(sessionKeyForHash(hash))
            if (raw == null) {
                redis.opsForSet().remove(indexKey, hash)
                continue
            }
            val session = objectMapper.readValue(raw, SessionRecord::class.java)
            if (session.tenantId == tenantId && session.userId == userId) sessions += session
        }
        return sessions.sortedByDescending { it.issuedAt }
    }

    /** Ends every live session for the user. Returns how many were actually ended. */
    fun terminateAllForUser(tenantId: UUID, userId: UUID, reason: String?): Int {
        val indexKey = userIndexKey(tenantId, userId)
        var ended = 0
        for (hash in redis.opsForSet().members(indexKey).orEmpty()) {
            if (terminateByHash(hash, indexKey, tenantId, userId, reason) != null) ended++
        }
        return ended
    }

    /** Ends one specific session of the user, identified by its sessionId. */
    fun terminateOneForUser(tenantId: UUID, userId: UUID, sessionId: UUID, reason: String?) {
        val indexKey = userIndexKey(tenantId, userId)
        for (hash in redis.opsForSet().members(indexKey).orEmpty()) {
            val raw = redis.opsForValue().get(sessionKeyForHash(hash)) ?: continue
            val session = objectMapper.readValue(raw, SessionRecord::class.java)
            if (session.sessionId == sessionId) {
                terminateByHash(hash, indexKey, tenantId, userId, reason) ?: throw SessionNotFoundException()
                return
            }
        }
        throw SessionNotFoundException()
    }

    private fun terminateByHash(hash: String, indexKey: String, tenantId: UUID, userId: UUID, reason: String?): SessionRecord? {
        val raw = redis.opsForValue().getAndDelete(sessionKeyForHash(hash))
        redis.opsForSet().remove(indexKey, hash)
        if (raw == null) return null
        val session = objectMapper.readValue(raw, SessionRecord::class.java)
        if (session.tenantId != tenantId || session.userId != userId) return null
        publishTerminated(session, reason)
        return session
    }

    private fun publishTerminated(session: SessionRecord, reason: String?) {
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
        fun sessionKey(token: String): String = sessionKeyForHash(SessionTokens.hash(token))
        fun sessionKeyForHash(hash: String): String = "session:$hash"
        fun userIndexKey(tenantId: UUID, userId: UUID): String = "user-sessions:$tenantId:$userId"
        fun idempotencyKey(tenantId: UUID, key: String): String = "session-idem:$tenantId:$key"
    }
}
