package com.iamplatform.tenant

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
enum class RemoteUserStatus { ACTIVE, SUSPENDED }

data class RemoteUser(val id: UUID, val tenantId: UUID, val role: RemoteUserRole, val groupId: UUID? = null)

data class RemoteUserListEntry(
    val id: UUID,
    val tenantId: UUID,
    val email: String,
    val displayName: String,
    val status: RemoteUserStatus,
    val role: RemoteUserRole,
    val groupId: UUID? = null,
)

data class CreateRemoteUserRequest(
    val tenantId: UUID,
    val email: String,
    val displayName: String,
    val password: String? = null,
    val role: RemoteUserRole? = null,
)

data class CreatedRemoteUser(val id: UUID, val tenantId: UUID, val email: String, val displayName: String, val role: RemoteUserRole)

/**
 * Added for Service 14 (iam-admin-console) -- used only by AdminAccessGuard
 * to resolve a validated session's role. Only `id`/`tenantId`/`role` are
 * declared even though iam-identity-svc's User response has more fields --
 * Jackson ignores the rest by default.
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

    // Added for the admin-console "create user" self-service page --
    // proxies straight through to iam-identity-svc's own POST /api/v1/users,
    // which is mTLS-only inbound (no browser SPA can call it directly).
    fun createUser(request: CreateRemoteUserRequest): CreatedRemoteUser =
        client.post("/api/v1/users", request, CreatedRemoteUser::class.java)

    // Added for the admin-console "Switch to user" picker. Array class, not
    // List -- Jackson can deserialize a JSON array directly into a Class
    // reference (type erasure means ResilientHttpClient.get can't accept a
    // generic List<T> target), converted to a list below.
    fun listUsers(tenantId: UUID): List<RemoteUserListEntry> =
        client.get("/api/v1/users?tenantId=$tenantId", Array<RemoteUserListEntry>::class.java).toList()
}
