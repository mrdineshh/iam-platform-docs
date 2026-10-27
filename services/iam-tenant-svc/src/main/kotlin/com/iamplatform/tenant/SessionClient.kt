package com.iamplatform.tenant

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestClient
import java.time.Instant
import java.util.UUID

data class RemoteSession(val sessionId: UUID, val tenantId: UUID, val userId: UUID, val expiresAt: Instant)

data class IssueRemoteSessionRequest(val tenantId: UUID, val userId: UUID, val sourceIp: String? = null)
data class IssuedRemoteSession(val token: String, val sessionId: UUID, val tenantId: UUID, val userId: UUID, val expiresAt: Instant)

/**
 * Added for Service 14 (iam-admin-console) -- this service's first outbound
 * HTTP call. Used only by the new admin-gated endpoints (see AdminAccessGuard)
 * to confirm a caller's X-Session-Token is live before trusting anything else
 * about the request.
 */
@Component
class SessionClient(
    @Value("\${iam.dependencies.session-svc}") baseUrl: String,
    restClientBuilder: RestClient.Builder,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
) {
    private val client = ResilientHttpClient(
        resilientRestClientBuilder(restClientBuilder, baseUrl).build(),
        circuitBreakerRegistry,
        retryRegistry,
        "session-svc",
    )

    fun find(sessionToken: String): RemoteSession? =
        try {
            client.get("/api/v1/sessions", RemoteSession::class.java, headers = mapOf("X-Session-Token" to sessionToken))
        } catch (ex: HttpClientErrorException.NotFound) {
            null
        }

    // Added for the admin-console "Switch to user" impersonation feature --
    // mints a brand-new, fully real session for the target user, same as if
    // they'd logged in themselves (no password/MFA involved, since the
    // caller here already proved they're an admin -- see
    // AdminUserController's sibling, ImpersonateController, for the guard
    // and the audit event this always publishes).
    fun issue(tenantId: UUID, userId: UUID, sourceIp: String?): IssuedRemoteSession =
        client.post("/api/v1/sessions", IssueRemoteSessionRequest(tenantId, userId, sourceIp), IssuedRemoteSession::class.java)

    // Per-user session management. `reason` must be a URL-safe token (no
    // spaces or percent signs): ResilientHttpClient passes the URI through
    // RestClient's template encoder, which would double-encode anything else.
    fun listForUser(tenantId: UUID, userId: UUID): List<RemoteSessionRecord> =
        client.get("/api/v1/sessions/by-user/$userId?tenantId=$tenantId", Array<RemoteSessionRecord>::class.java).toList()

    fun terminateAllForUser(tenantId: UUID, userId: UUID, reason: String) {
        client.delete("/api/v1/sessions/by-user/$userId?tenantId=$tenantId&reason=$reason")
    }

    fun terminateOneForUser(tenantId: UUID, userId: UUID, sessionId: UUID, reason: String) {
        try {
            client.delete("/api/v1/sessions/by-user/$userId/$sessionId?tenantId=$tenantId&reason=$reason")
        } catch (ex: HttpClientErrorException.NotFound) {
            throw SessionNotFoundForRevokeException()
        }
    }
}

data class RemoteSessionRecord(
    val sessionId: UUID,
    val tenantId: UUID,
    val userId: UUID,
    val sourceIp: String?,
    val deviceId: String?,
    val issuedAt: Instant,
    val expiresAt: Instant,
)

class SessionNotFoundForRevokeException : RuntimeException("Session not found, expired, or already ended")
