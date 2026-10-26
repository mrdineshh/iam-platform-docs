package com.iamplatform.device

import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Pattern
import java.util.UUID

data class EnrollDeviceRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotNull
    val userId: UUID,

    val fcmToken: String? = null,
)

data class EnrollDeviceResponse(
    val deviceId: UUID,
    val status: DeviceStatus,
    val totpSecret: String,
    val provisioningUri: String,
)

data class EnsurePendingRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotNull
    val userId: UUID,
)

/**
 * `alreadyActive = true` means this user has a working, already-activated
 * device -- there's nothing to show them, the caller (iam-auth-svc) should
 * ask for a code instead of enrollment.
 */
data class EnsurePendingResponse(
    val alreadyActive: Boolean,
    val deviceId: UUID? = null,
    val totpSecret: String? = null,
    val provisioningUri: String? = null,
)

data class ResetAndEnrollRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotNull
    val userId: UUID,
)

data class ResetAndEnrollResponse(
    val deviceId: UUID,
    val totpSecret: String,
    val provisioningUri: String,
)

data class TotpVerifyRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotNull
    val userId: UUID,

    @field:Pattern(regexp = "^\\d{6}$")
    val code: String,
)

data class TotpVerifyResponse(
    val valid: Boolean,
    val status: DeviceStatus2,
)

/** Distinct from [DeviceStatus] -- LOCKED is a verify-time outcome, not a persisted device state. */
enum class DeviceStatus2 { PENDING, ACTIVE, LOCKED }

data class PushSendRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotNull
    val userId: UUID,
)

enum class PushResult { APPROVED, DENIED, TIMEOUT }

data class PushSendResponse(
    val challengeId: UUID,
    val result: PushResult,
)

data class PushRespondRequest(
    @field:NotNull
    val challengeId: UUID,

    @field:NotNull
    val approve: Boolean,
)
