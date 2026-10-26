package com.iamplatform.auth

import com.iamplatform.auth.client.DeviceClient
import com.iamplatform.auth.client.IdentityClient
import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import org.springframework.stereotype.Service
import java.util.UUID

data class BreakGlassResetRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    val email: String,

    @field:NotBlank
    val breakGlassToken: String,
)

data class BreakGlassResetResponse(
    val userId: UUID,
    val totpSecret: String,
    val provisioningUri: String,
)

class BreakGlassTokenInvalidException : RuntimeException("Invalid break-glass token")
class BreakGlassUserNotFoundException(email: String) : RuntimeException("No user '$email' in this tenant")

@Service
class BreakGlassService(
    private val tokenProvider: BreakGlassTokenProvider,
    private val identityClient: IdentityClient,
    private val deviceClient: DeviceClient,
    private val auditPublisher: AuditPublisher,
) {

    /**
     * Resets a user's 2FA device when every normal path is unavailable --
     * the only admin locked out, with nobody else to use the admin-gated
     * reset. Requires possession of the per-tenant break-glass token
     * (OpenBao-only, never exposed in-app, see BreakGlassTokenProvider),
     * not a session -- that's the whole point of break-glass. AP-8: every
     * use is immutably audited regardless of outcome.
     */
    fun resetTwoFactor(request: BreakGlassResetRequest, sourceIp: String?): BreakGlassResetResponse {
        if (!tokenProvider.matches(request.tenantId, request.breakGlassToken)) {
            audit(request.tenantId, request.email, AuditResult.DENIED, "invalid break-glass token", sourceIp)
            throw BreakGlassTokenInvalidException()
        }

        val user = identityClient.listUsers(request.tenantId).find { it.email.equals(request.email, ignoreCase = true) }
            ?: run {
                audit(request.tenantId, request.email, AuditResult.FAILURE, "user not found", sourceIp)
                throw BreakGlassUserNotFoundException(request.email)
            }

        val result = deviceClient.resetAndEnroll(request.tenantId, user.id)
        audit(request.tenantId, request.email, AuditResult.SUCCESS, "2FA device reset via break-glass token", sourceIp)

        return BreakGlassResetResponse(
            userId = user.id,
            totpSecret = result.totpSecret,
            provisioningUri = result.provisioningUri,
        )
    }

    private fun audit(tenantId: UUID, targetEmail: String, result: AuditResult, reason: String, sourceIp: String?) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "break-glass-operator",
                action = "auth.break_glass_2fa_reset",
                result = result,
                reason = "target=$targetEmail: $reason",
                sourceIp = sourceIp,
            ),
        )
    }
}
