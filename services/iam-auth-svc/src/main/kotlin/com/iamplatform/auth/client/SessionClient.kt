package com.iamplatform.auth.client

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.time.Instant
import java.util.UUID

/** Where and on what a session was opened (see ClientContext); stored on the session for the admin Sessions view. */
data class SessionContext(
    val userAgent: String? = null,
    val country: String? = null,
    val region: String? = null,
    val city: String? = null,
)

data class IssueSessionRequest(
    val tenantId: UUID,
    val userId: UUID,
    val sourceIp: String? = null,
    val userAgent: String? = null,
    val country: String? = null,
    val region: String? = null,
    val city: String? = null,
)
data class IssuedSession(val token: String, val sessionId: UUID, val expiresAt: Instant)

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

    // Idempotency-Key prevents a Resilience4j retry (e.g. after a read
    // timeout where the first attempt actually succeeded server-side) from
    // issuing two sessions for one login. correlationId is unique per
    // request, so it doubles as the key.
    fun issue(tenantId: UUID, userId: UUID, sourceIp: String?, idempotencyKey: String, context: SessionContext?): IssuedSession =
        client.post(
            "/api/v1/sessions",
            IssueSessionRequest(tenantId, userId, sourceIp, context?.userAgent, context?.country, context?.region, context?.city),
            IssuedSession::class.java,
            headers = mapOf("Idempotency-Key" to idempotencyKey),
        )

    // Pass the raw reason -- RestClient's own URI template encoding handles
    // it correctly in one pass. Pre-encoding here (as this used to do via
    // URLEncoder) double-encodes: RestClient encodes the already-`%`-escaped
    // string a second time, and the server's one @RequestParam decode pass
    // only undoes one of the two layers, leaving literal `%27` etc. in the
    // stored audit reason. Found while verifying Service 10's TEST GATE
    // (docs/DECISIONS.md, Service 10 entry) -- the first termination reason
    // in this whole project to contain a quote character.
    fun terminate(token: String, reason: String) {
        client.delete(
            "/api/v1/sessions?reason=$reason",
            headers = mapOf("X-Session-Token" to token),
        )
    }
}
