package com.iamplatform.tenant

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.time.Instant
import java.util.UUID

data class RemoteGroup(val id: UUID, val tenantId: UUID, val name: String, val createdAt: Instant)
data class CreateRemoteGroupRequest(val tenantId: UUID, val name: String)
data class AssignRemoteGroupRequest(val groupId: UUID?)

/**
 * Proxies to iam-identity-svc's new /api/v1/groups + PATCH .../group --
 * same mTLS-only-inbound reasoning as IdentityClient's other methods.
 */
@Component
class GroupClient(
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

    fun createGroup(tenantId: UUID, name: String): RemoteGroup =
        client.post("/api/v1/groups", CreateRemoteGroupRequest(tenantId, name), RemoteGroup::class.java)

    fun listGroups(tenantId: UUID): List<RemoteGroup> =
        client.get("/api/v1/groups?tenantId=$tenantId", Array<RemoteGroup>::class.java).toList()

    fun assignGroup(userId: UUID, groupId: UUID?): RemoteUser =
        client.patch("/api/v1/users/$userId/group", AssignRemoteGroupRequest(groupId), RemoteUser::class.java)

    fun deleteGroup(id: UUID): Unit = client.delete("/api/v1/groups/$id")
}
