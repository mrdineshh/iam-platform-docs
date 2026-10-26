package com.iamplatform.oidc

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import tools.jackson.databind.ObjectMapper
import java.security.SecureRandom
import java.time.Duration
import java.util.Base64
import java.util.UUID

data class PendingSamlRequest(
    val samlSpId: UUID,
    val tenantId: UUID,
    val spEntityId: String,
    val acsUrl: String,
    val inResponseTo: String?,
    val relayState: String?,
)

/**
 * Holds a parsed, SP-resolved AuthnRequest between GET /saml/sso (SP
 * redirects the browser here) and POST /saml/complete (iam-login-portal
 * calls back once the user has actually authenticated) -- same role and
 * lifetime reasoning as AuthorizationCodeStore's codes, just keyed by an
 * opaque request ID instead of client_id/redirect_uri query params
 * (iam-login-portal's /saml page only needs this one ID, not the raw SAML
 * XML). Single-use via GETDEL on complete.
 */
@Component
class SamlRequestStore(
    private val redis: StringRedisTemplate,
    private val objectMapper: ObjectMapper,
) {
    private val random = SecureRandom()

    fun store(data: PendingSamlRequest): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        val id = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        redis.opsForValue().set(key(id), objectMapper.writeValueAsString(data), Duration.ofMinutes(10))
        return id
    }

    fun consume(id: String): PendingSamlRequest? {
        val raw = redis.opsForValue().getAndDelete(key(id)) ?: return null
        return objectMapper.readValue(raw, PendingSamlRequest::class.java)
    }

    private fun key(id: String): String = "saml:request:$id"
}
