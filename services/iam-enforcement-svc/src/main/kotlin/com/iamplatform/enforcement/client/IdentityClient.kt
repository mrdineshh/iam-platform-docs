package com.iamplatform.enforcement.client

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestClient
import java.util.UUID

enum class RemoteUserStatus { ACTIVE, SUSPENDED }

data class RemoteUser(val id: UUID, val tenantId: UUID, val status: RemoteUserStatus)

/**
 * Added 2026-10-26 (docs/DECISIONS.md) so continuous enforcement can
 * confirm a session's user is still real and ACTIVE, not just that the
 * session itself hasn't expired -- see EnforcementService's use of this.
 */
@Component
class IdentityClient(
    @Value("\${iam.dependencies.identity-svc}") baseUrl: String,
    restClientBuilder: RestClient.Builder,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
) {
    private val client = ResilientHttpClient(
        resilientRestClientBuilder(restClientBuilder, baseUrl).build(),
        circuitBreakerRegistry,
        retryRegistry,
        "identity-svc",
    )

    /** Returns null if the user doesn't exist -- caller decides how to surface that. */
    fun findUser(userId: UUID): RemoteUser? =
        try {
            client.get("/api/v1/users/$userId", RemoteUser::class.java)
        } catch (ex: HttpClientErrorException.NotFound) {
            null
        }
}
