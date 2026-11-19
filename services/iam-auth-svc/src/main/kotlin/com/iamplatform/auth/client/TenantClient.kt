package com.iamplatform.auth.client

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestClient
import java.util.UUID

data class VerifyDeviceProofRequest(val userId: UUID, val deviceId: UUID, val signature: String, val origin: String)
data class VerifiedDeviceProof(val deviceId: UUID, val assuranceLevel: String)

/** [role] is "ADMIN" or "USER"; [deviceId] is the laptop whose signed proof was just verified, or null when there was none. */
data class LoginDeviceCheckRequest(val tenantId: UUID, val userId: UUID, val role: String, val deviceId: String?)

/** [code] is DEVICE_REQUIRED, DEVICE_NOT_APPROVED or DEVICE_NON_COMPLIANT when [allowed] is false. */
data class LoginDeviceCheckResponse(val allowed: Boolean, val code: String? = null, val detail: String? = null)

/**
 * Asks iam-tenant-svc whether a sign-in came from an enrolled laptop (device-bound sign-in, see
 * docs/specs/device-bound-signin-SPEC.md). The answer only ever ADDS a device to a session: nothing here can make a
 * sign-in fail, so every caller treats "no" and "could not ask" the same way -- no device.
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

    /**
     * The platform sign-in rule: may this person become a session, given the laptop (if any) they proved? Unlike
     * [verifyDeviceProof] this CAN stop a sign-in, so the caller must treat an error as a refusal, never as "allowed".
     */
    fun checkLoginDevice(request: LoginDeviceCheckRequest): LoginDeviceCheckResponse =
        client.post("/internal/login-device-check", request, LoginDeviceCheckResponse::class.java)

    /** The verified device, or null when the platform did not accept the proof (HTTP 401). */
    fun verifyDeviceProof(challengeId: UUID, request: VerifyDeviceProofRequest): VerifiedDeviceProof? =
        try {
            client.post("/internal/device-challenges/$challengeId/verify", request, VerifiedDeviceProof::class.java)
        } catch (ex: HttpClientErrorException.Unauthorized) {
            null
        }
}
