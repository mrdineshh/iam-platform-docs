package com.iamplatform.identity

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestClient
import java.util.UUID

/**
 * Only reads through the published contract (GET /api/v1/tenants/{id}) --
 * never touches iam-tenant-svc's database directly (BUILD_PLAN.md Section
 * 4.4). A 404 here is a legitimate business outcome (bad tenantId), not an
 * iam-tenant-svc failure -- see the "tenant-svc" circuit breaker/retry
 * instances in application.yml, which are configured to ignore it so a
 * client typo-ing tenant IDs can never trip the breaker or trigger retries.
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

    fun exists(tenantId: UUID): Boolean =
        try {
            client.get("/api/v1/tenants/$tenantId", TenantRef::class.java)
            true
        } catch (ex: HttpClientErrorException.NotFound) {
            false
        }

    private data class TenantRef(val id: UUID)
}
