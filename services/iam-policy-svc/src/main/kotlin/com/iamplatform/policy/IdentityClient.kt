package com.iamplatform.policy

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestClient
import java.util.UUID

enum class RemoteUserRole { ADMIN, USER }

data class RemoteUser(val id: UUID, val tenantId: UUID, val role: RemoteUserRole)

/** Added for Service 14 (iam-admin-console) -- used only by AdminAccessGuard. */
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
