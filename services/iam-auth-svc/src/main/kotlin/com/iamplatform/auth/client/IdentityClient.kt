package com.iamplatform.auth.client

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.util.UUID

enum class RemoteUserStatus { ACTIVE, SUSPENDED }

// Added for Service 14 (iam-admin-console) -- see docs/DECISIONS.md.
enum class RemoteUserRole { ADMIN, USER }

data class VerifyPasswordRequest(val tenantId: UUID, val email: String, val password: String)
data class VerifyPasswordResponse(
    val valid: Boolean,
    val userId: UUID? = null,
    val status: RemoteUserStatus? = null,
    val role: RemoteUserRole? = null,
    val groupId: UUID? = null,
    // Set (with valid=false) when the correct password was given for a locked
    // account -- see iam-identity-svc's verifyPassword for why it isn't
    // revealed to a wrong guess.
    val locked: Boolean = false,
    val permanentlyLocked: Boolean = false,
)

// Added for the break-glass 2FA reset path (BreakGlassService) -- it needs
// to resolve a user by email without a password, which verify-password
// can't do.
data class RemoteUserListEntry(val id: UUID, val email: String, val role: RemoteUserRole)

/**
 * The only path allowed to check a password (AP-3-adjacent: iam-auth-svc
 * never touches password hashes itself -- iam-identity-svc owns that,
 * see docs/DECISIONS.md, Service 7 entry). verify-password always returns
 * 200 (never a business 404), so unlike TenantClient there's no NotFound
 * case to exempt from the circuit breaker.
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

    fun verifyPassword(tenantId: UUID, email: String, password: String): VerifyPasswordResponse =
        client.post(
            "/api/v1/users/verify-password",
            VerifyPasswordRequest(tenantId, email, password),
            VerifyPasswordResponse::class.java,
        )

    fun listUsers(tenantId: UUID): List<RemoteUserListEntry> =
        client.get("/api/v1/users?tenantId=$tenantId", Array<RemoteUserListEntry>::class.java).toList()
}
