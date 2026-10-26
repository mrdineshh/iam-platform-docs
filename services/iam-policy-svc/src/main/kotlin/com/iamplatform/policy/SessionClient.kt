package com.iamplatform.policy

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
 * Added for Service 14 (iam-admin-console) -- this service's first outbound
 * HTTP call (previously "pure logic + storage, no outbound calls" per its
 * own contract description -- see docs/DECISIONS.md for the corrected
 * description). Used only by the new admin-gated endpoints.
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
}
