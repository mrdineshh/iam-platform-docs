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

data class RemoteUser(val id: UUID, val tenantId: UUID, val role: RemoteUserRole, val groupId: UUID? = null, val email: String? = null)

data class RemoteUserListEntry(
    val id: UUID,
    val tenantId: UUID,
    val email: String,
    val displayName: String,
    val status: RemoteUserStatus,
    val role: RemoteUserRole,
    val groupId: UUID? = null,
    val locked: Boolean = false,
    val lockedUntil: java.time.Instant? = null,
    val permanentlyLocked: Boolean = false,
)

/** The body iam-identity-svc returns on a 4xx -- only what the console needs to show. */
data class UpstreamErrorBody(val message: String? = null, val errorCode: String? = null)

/** A 400 from a downstream service whose message is meant for the admin (e.g. a weak password). */
class UpstreamBadRequestException(message: String, val errorCode: String?) : RuntimeException(message)

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
        try {
            client.post("/api/v1/users", request, CreatedRemoteUser::class.java)
        } catch (ex: HttpClientErrorException.BadRequest) {
            // e.g. WEAK_PASSWORD: the identity service's message names exactly
            // which of the tenant's rules the password broke, so pass it through.
            val body = runCatching { ex.getResponseBodyAs(UpstreamErrorBody::class.java) }.getOrNull()
            throw UpstreamBadRequestException(body?.message ?: "The request was rejected.", body?.errorCode)
        }

    // Admin-initiated unlock after a lockout (FR-3.5); the admin is gated and
    // audited by AdminUserController, not here.
    fun unlockUser(userId: UUID): Unit {
        client.post("/api/v1/users/$userId/unlock", emptyMap<String, String>(), RemoteUserListEntry::class.java)
    }

    // Added for the admin-console "Switch to user" picker. Array class, not
    // List -- Jackson can deserialize a JSON array directly into a Class
    // reference (type erasure means ResilientHttpClient.get can't accept a
    // generic List<T> target), converted to a list below.
    fun listUsers(tenantId: UUID): List<RemoteUserListEntry> =
        client.get("/api/v1/users?tenantId=$tenantId", Array<RemoteUserListEntry>::class.java).toList()

    // Hard delete -- "deleted from everywhere" (2026-10-26, docs/DECISIONS.md).
    fun deleteUser(userId: UUID): Unit = client.delete("/api/v1/users/$userId")
}
