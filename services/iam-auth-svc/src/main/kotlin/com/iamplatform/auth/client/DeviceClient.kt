package com.iamplatform.auth.client

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.time.Duration
import java.util.UUID

enum class RemoteDeviceStatus { PENDING, ACTIVE, LOCKED }
enum class RemotePushResult { APPROVED, DENIED, TIMEOUT }

data class TotpVerifyResult(val valid: Boolean, val status: RemoteDeviceStatus)
data class PushSendResult(val challengeId: UUID, val result: RemotePushResult)
data class EnsurePendingResult(
    val alreadyActive: Boolean,
    val deviceId: UUID? = null,
    val totpSecret: String? = null,
    val provisioningUri: String? = null,
)
data class ResetAndEnrollResult(
    val deviceId: UUID,
    val totpSecret: String,
    val provisioningUri: String,
)

/**
 * Read timeout is 65s, not the platform default 5s -- /push/send blocks on
 * the far side for up to 60s waiting on the mobile app's response (confirmed
 * design, docs/DECISIONS.md Service 9 entry). totp/verify tolerates the same
 * generous timeout harmlessly; it always returns in milliseconds in
 * practice.
 */
@Component
class DeviceClient(
    @Value("\${iam.dependencies.device-svc}") baseUrl: String,
    restClientBuilder: RestClient.Builder,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
) {
    private val client = ResilientHttpClient(
        resilientRestClientBuilder(restClientBuilder, baseUrl, readTimeout = Duration.ofSeconds(65)).build(),
        circuitBreakerRegistry,
        retryRegistry,
        "device-svc",
    )

    fun verifyTotp(tenantId: UUID, userId: UUID, code: String): TotpVerifyResult =
        client.post(
            "/api/v1/devices/totp/verify",
            mapOf("tenantId" to tenantId, "userId" to userId, "code" to code),
            TotpVerifyResult::class.java,
        )

    fun sendPush(tenantId: UUID, userId: UUID): PushSendResult =
        client.post(
            "/api/v1/devices/push/send",
            mapOf("tenantId" to tenantId, "userId" to userId),
            PushSendResult::class.java,
        )

    fun ensurePending(tenantId: UUID, userId: UUID): EnsurePendingResult =
        client.post(
            "/api/v1/devices/ensure-pending",
            mapOf("tenantId" to tenantId, "userId" to userId),
            EnsurePendingResult::class.java,
        )

    fun resetAndEnroll(tenantId: UUID, userId: UUID): ResetAndEnrollResult =
        client.post(
            "/api/v1/devices/reset-and-enroll",
            mapOf("tenantId" to tenantId, "userId" to userId),
            ResetAndEnrollResult::class.java,
        )
}
