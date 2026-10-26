package com.iamplatform.enforcement.client

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

data class RemoteSession(
    val sessionId: UUID,
    val tenantId: UUID,
    val userId: UUID,
    val sourceIp: String? = null,
    val deviceId: String? = null,
    val issuedAt: Instant,
    val expiresAt: Instant,
)

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

    /** Returns null for unknown/expired/already-terminated -- never treated as a transport error. */
    fun validate(token: String): RemoteSession? =
        try {
            client.get("/api/v1/sessions", RemoteSession::class.java, headers = mapOf("X-Session-Token" to token))
        } catch (ex: HttpClientErrorException.NotFound) {
            null
        }

    // Raw reason, not pre-encoded -- see docs/DECISIONS.md Service 10 entry
    // for the double-encoding bug this avoids (also fixed in iam-auth-svc's
    // identical SessionClient.terminate).
    fun terminate(token: String, reason: String) {
        client.delete(
            "/api/v1/sessions?reason=$reason",
            headers = mapOf("X-Session-Token" to token),
        )
    }
}
