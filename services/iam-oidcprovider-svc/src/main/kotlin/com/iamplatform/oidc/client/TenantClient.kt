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

data class RemoteOidcClient(
    val clientId: UUID,
    val tenantId: UUID,
    val name: String,
    val redirectUris: List<String>,
    val createdAt: Instant,
)

data class RemoteSamlSp(
    val id: UUID,
    val tenantId: UUID,
    val name: String,
    val spEntityId: String,
    val acsUrl: String,
    val createdAt: Instant,
)

data class VerifyClientSecretRequest(val clientSecret: String)
data class VerifyClientSecretResponse(val valid: Boolean, val tenantId: UUID? = null)

// Added for Service 13 (iam-login-portal) -- resolves the client's tenant's
// subdomain so GET /authorize can redirect to the correct tenant-scoped
// login portal URL. Existing endpoint, no iam-tenant-svc contract change.
data class RemoteTenant(
    val id: UUID,
    val name: String,
    val subdomain: String,
    val status: String,
    val createdAt: Instant,
)

/**
 * Only reads through the published contract -- never iam-tenant-svc's
 * database directly (BUILD_PLAN.md Section 4.4). A 404 on lookup is a
 * legitimate business outcome (bad/unknown client_id), exempted from the
 * circuit breaker/retry the same way iam-identity-svc's own TenantClient
 * exempts a missing tenant (Service 4 precedent).
 */
@Component
class TenantClient(
    @Value("\${iam.dependencies.tenant-svc}") baseUrl: String,
    restClientBuilder: RestClient.Builder,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
) {
    private val client = ResilientHttpClient(
        resilientRestClientBuilder(restClientBuilder, baseUrl).build(),
        circuitBreakerRegistry,
        retryRegistry,
        "tenant-svc",
    )

    fun findClient(clientId: UUID): RemoteOidcClient? =
        try {
            client.get("/api/v1/oidc-clients/$clientId", RemoteOidcClient::class.java)
        } catch (ex: HttpClientErrorException.NotFound) {
            null
        }

    fun findTenant(tenantId: UUID): RemoteTenant? =
        try {
            client.get("/api/v1/tenants/$tenantId", RemoteTenant::class.java)
        } catch (ex: HttpClientErrorException.NotFound) {
            null
        }

    fun verifySecret(clientId: UUID, secret: String): VerifyClientSecretResponse =
        client.post(
            "/api/v1/oidc-clients/$clientId/verify-secret",
            VerifyClientSecretRequest(secret),
            VerifyClientSecretResponse::class.java,
        )

    // Deliberately NOT pre-encoded with URLEncoder -- RestClient's
    // uri(String) treats this as a URI template and encodes it itself; an
    // already-percent-encoded value gets double-encoded (the literal '%'
    // becomes '%25'), which silently breaks the lookup. Found live:
    // tenant-svc returned the SP correctly when called with curl's own
    // encoding, but 404'd through this client until the manual encode was
    // removed.
    fun findSamlSpByEntityId(entityId: String): RemoteSamlSp? =
        try {
            client.get("/api/v1/saml-sps/by-entity-id?entityId=$entityId", RemoteSamlSp::class.java)
        } catch (ex: HttpClientErrorException.NotFound) {
            null
        }
}
