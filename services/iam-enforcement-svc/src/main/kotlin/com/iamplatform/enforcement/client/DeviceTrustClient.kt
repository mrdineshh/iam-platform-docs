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

data class RemoteDeviceTrustStatus(val deviceId: UUID, val tenantId: UUID, val lifecycleStatus: String)

/**
 * Endpoint Device Trust spec Section 4 ("PEP ... Final server-side access
 * decision", "A protected application must not trust a client-supplied
 * device ID alone"). Calls iam-tenant-svc's internal (not admin-gated,
 * mTLS-trusted-caller-only -- same pattern as iam-oidcprovider-svc's own
 * InternalController) device-trust-status lookup, so continuous
 * enforcement (EnforcementService) can confirm a session's claimed device
 * is still APPROVED on every request, not just at login.
 */
@Component
class DeviceTrustClient(
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

    /** Returns null if the device doesn't exist (or belongs to a different tenant) -- caller treats that as untrusted. */
    fun findDeviceTrustStatus(tenantId: UUID, deviceId: UUID): RemoteDeviceTrustStatus? =
        try {
            client.get("/internal/devices/$deviceId?tenantId=$tenantId", RemoteDeviceTrustStatus::class.java)
        } catch (ex: HttpClientErrorException.NotFound) {
            null
        }
}
