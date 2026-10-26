package com.iamplatform.oidc.client

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

/**
 * Confirms the underlying platform session is still live before answering
 * /userinfo (BUILD_PLAN.md Service 11: "iam-session-svc to confirm
 * validity") -- so a session iam-enforcement-svc kills mid-flight (AP-2)
 * correctly invalidates the OIDC access token immediately too, not just at
 * the access token's own separate expiry.
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

    // Raw reason, not pre-encoded -- see docs/DECISIONS.md Service 10 entry
    // for the double-encoding bug this avoids (also fixed in
    // iam-enforcement-svc's and iam-auth-svc's identical SessionClient).
    fun terminate(sessionToken: String, reason: String) {
        client.delete(
            "/api/v1/sessions?reason=$reason",
            headers = mapOf("X-Session-Token" to sessionToken),
        )
    }
}
