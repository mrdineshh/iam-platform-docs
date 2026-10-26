package com.iamplatform.device

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Service
import tools.jackson.databind.ObjectMapper
import java.time.Duration
import java.time.Instant
import java.util.UUID

enum class ChallengeStatus { PENDING, APPROVED, DENIED }

data class PushChallenge(
    val challengeId: UUID,
    val tenantId: UUID,
    val userId: UUID,
    val deviceId: UUID,
    val status: ChallengeStatus,
    val createdAt: Instant,
)

/**
 * Pending-approval state lives entirely in Valkey, never Postgres
 * (BUILD_PLAN.md Service 9: "pending-approval state in its own Valkey
 * keyspace, 60s timeout") -- same reasoning as iam-session-svc using Valkey
 * for session state: this is ephemeral, not an audit/system-of-record fact.
 */
@Service
class PushChallengeService(
    private val redis: StringRedisTemplate,
    private val objectMapper: ObjectMapper,
    private val properties: PushPolicyProperties,
) {
    fun create(tenantId: UUID, userId: UUID, deviceId: UUID): PushChallenge {
        val challenge = PushChallenge(
            challengeId = UUID.randomUUID(),
            tenantId = tenantId,
            userId = userId,
            deviceId = deviceId,
            status = ChallengeStatus.PENDING,
            createdAt = Instant.now(),
        )
        save(challenge)
        return challenge
    }

    fun find(challengeId: UUID): PushChallenge? =
        redis.opsForValue().get(key(challengeId))?.let { objectMapper.readValue(it, PushChallenge::class.java) }

    /** Returns false if the challenge doesn't exist or is no longer PENDING (already resolved/expired). */
    fun resolve(challengeId: UUID, approve: Boolean): Boolean {
        val challenge = find(challengeId) ?: return false
        if (challenge.status != ChallengeStatus.PENDING) return false
        save(challenge.copy(status = if (approve) ChallengeStatus.APPROVED else ChallengeStatus.DENIED))
        return true
    }

    fun delete(challengeId: UUID) {
        redis.delete(key(challengeId))
    }

    private fun save(challenge: PushChallenge) {
        redis.opsForValue().set(
            key(challenge.challengeId),
            objectMapper.writeValueAsString(challenge),
            Duration.ofSeconds(properties.challengeTtlSeconds),
        )
    }

    private fun key(challengeId: UUID) = "push-challenge:$challengeId"
}
