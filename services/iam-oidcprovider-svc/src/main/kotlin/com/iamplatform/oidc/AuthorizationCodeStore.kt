package com.iamplatform.oidc

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import tools.jackson.databind.ObjectMapper
import java.security.SecureRandom
import java.time.Duration
import java.util.Base64
import java.util.UUID

data class AuthorizationCodeData(
    val clientId: UUID,
    val tenantId: UUID,
    val userId: UUID,
    val email: String,
    val redirectUri: String,
    val scope: String,
    val sessionToken: String,
)

/**
 * Single-use, short-lived (60s) authorization codes in Valkey -- same
 * infra iam-session-svc uses for sessions, own keyspace prefix so the two
 * never collide (iam-session-svc's own database-per-service equivalent for
 * a key-value store). GETDEL on exchange, same atomicity reasoning as
 * iam-session-svc's own termination (Service 6): a code can be redeemed
 * exactly once, never replayed.
 */
@Component
class AuthorizationCodeStore(
    private val redis: StringRedisTemplate,
    private val objectMapper: ObjectMapper,
) {
    private val random = SecureRandom()

    fun issue(data: AuthorizationCodeData): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        val code = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        redis.opsForValue().set(key(code), objectMapper.writeValueAsString(data), Duration.ofSeconds(60))
        return code
    }

    fun redeem(code: String): AuthorizationCodeData? {
        val raw = redis.opsForValue().getAndDelete(key(code)) ?: return null
        return objectMapper.readValue(raw, AuthorizationCodeData::class.java)
    }

    private fun key(code: String): String = "oidc:code:$code"
}
