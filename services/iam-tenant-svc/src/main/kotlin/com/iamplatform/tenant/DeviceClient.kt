package com.iamplatform.tenant

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.util.UUID

data class RemoteEnrollRequest(val tenantId: UUID, val userId: UUID)
data class RemoteEnrollResponse(val deviceId: UUID, val status: String, val totpSecret: String, val provisioningUri: String)

data class RemoteTotpVerifyRequest(val tenantId: UUID, val userId: UUID, val code: String)
data class RemoteTotpVerifyResponse(val valid: Boolean, val status: String)

/**
 * Added for the admin-console "My Security" self-service 2FA enrollment
 * page -- iam-device-svc is mTLS-only inbound (no browser SPA can call it
 * directly), same reasoning as IdentityClient. Proxies straight through to
 * POST /api/v1/devices/enroll and POST /api/v1/devices/totp/verify.
 */
@Component
class DeviceClient(
    @Value("\${iam.dependencies.device-svc}") baseUrl: String,
    restClientBuilder: RestClient.Builder,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
) {
    private val client = ResilientHttpClient(
        resilientRestClientBuilder(restClientBuilder, baseUrl).build(),
        circuitBreakerRegistry,
        retryRegistry,
        "device-svc",
    )

    fun enroll(tenantId: UUID, userId: UUID): RemoteEnrollResponse =
        client.post("/api/v1/devices/enroll", RemoteEnrollRequest(tenantId, userId), RemoteEnrollResponse::class.java)

    fun verifyTotp(tenantId: UUID, userId: UUID, code: String): RemoteTotpVerifyResponse =
        client.post("/api/v1/devices/totp/verify", RemoteTotpVerifyRequest(tenantId, userId, code), RemoteTotpVerifyResponse::class.java)
}
