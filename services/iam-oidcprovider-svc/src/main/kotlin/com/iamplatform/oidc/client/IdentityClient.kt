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

data class RemoteUser(
    val id: UUID,
    val tenantId: UUID,
    val email: String,
    val displayName: String,
    val status: String,
    val createdAt: Instant,
)

/**
 * Added for Service 13 (iam-login-portal). POST /authorize/complete only
 * receives a session token, not an email -- unlike the old /authorize/login
 * form, which had the user type it directly. The email needed for the
 * id_token/access_token claims is fetched from iam-identity-svc by the
 * userId carried on the validated session instead. Existing endpoint
 * (GET /api/v1/users/{id}), no iam-identity-svc contract change.
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

    fun findUser(userId: UUID): RemoteUser? =
        try {
            client.get("/api/v1/users/$userId", RemoteUser::class.java)
        } catch (ex: HttpClientErrorException.NotFound) {
            null
        }
}
