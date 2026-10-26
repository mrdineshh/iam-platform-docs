package com.iamplatform.enforcement

import com.iamplatform.enforcement.client.EvaluateResponse
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import tools.jackson.databind.ObjectMapper
import java.time.Duration
import java.util.UUID

@ConfigurationProperties(prefix = "iam.enforcement")
data class EnforcementProperties(
    val policyCacheTtlSeconds: Long = 30,
)

/**
 * Bounds per-request overhead (BUILD_PLAN.md Service 10) by caching the
 * *policy decision* briefly -- never session validity, which is always
 * checked fresh against iam-session-svc (that's the entire point of
 * continuous enforcement, AP-2). Keyed by (tenant, user, country), not just
 * (tenant, country): a tenant-level cache alone would ignore per-user
 * OU/USER-scope policy overrides (AP-4) and silently apply the wrong
 * decision to a user with a more specific override. 30s default TTL,
 * confirmed with product owner.
 */
@Component
class PolicyDecisionCache(
    private val redis: StringRedisTemplate,
    private val objectMapper: ObjectMapper,
    private val properties: EnforcementProperties,
) {
    fun get(tenantId: UUID, userId: UUID, country: String): EvaluateResponse? =
        redis.opsForValue().get(key(tenantId, userId, country))
            ?.let { objectMapper.readValue(it, EvaluateResponse::class.java) }

    fun put(tenantId: UUID, userId: UUID, country: String, decision: EvaluateResponse) {
        redis.opsForValue().set(
            key(tenantId, userId, country),
            objectMapper.writeValueAsString(decision),
            Duration.ofSeconds(properties.policyCacheTtlSeconds),
        )
    }

    private fun key(tenantId: UUID, userId: UUID, country: String) = "policy-cache:$tenantId:$userId:$country"
}
