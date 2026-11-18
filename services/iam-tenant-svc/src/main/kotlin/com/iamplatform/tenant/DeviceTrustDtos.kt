package com.iamplatform.tenant

import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import java.time.Instant
import java.util.UUID

// ---- Enrollment (Section 6.1, Section 10.1/10.2) ----

data class EnrollmentStartRequest(
    // base64url (no padding) SHA-256 of the X.509 SubjectPublicKeyInfo DER the agent will submit to
    // /enrollment/complete -- see DeviceKeyThumbprint. Always 43 characters.
    @field:NotBlank
    @field:jakarta.validation.constraints.Pattern(regexp = "^[A-Za-z0-9_-]{43}$")
    val keyThumbprint: String,
)

data class EnrollmentStartResponse(
    val enrollmentTransactionId: UUID,
    val nonce: String,
    val expiresAt: Instant,
)

data class EnrollmentCompleteRequest(
    @field:NotNull val enrollmentTransactionId: UUID,
    @field:NotNull val deviceInstanceId: UUID,
    @field:NotBlank val platform: String, // "WINDOWS" only in Phase 1
    val osVersion: String? = null,
    val hostname: String? = null,
    val manufacturer: String? = null,
    val model: String? = null,
    // Privacy-controlled, optional (Section 5.2) -- the agent hashes these
    // itself before sending; this service never sees a raw serial/hardware UUID.
    val hardwareUuidHash: String? = null,
    val serialHash: String? = null,
    @field:NotBlank val ownership: String, // "CORPORATE" or "BYOD"
    @field:NotBlank val agentVersion: String,
    @field:NotBlank val publicKey: String, // base64
    @field:NotBlank val keyAlgorithm: String, // RSA2048, ECDSA_P256, ED25519
    @field:NotBlank val assuranceLevel: String, // HARDWARE_TPM, HARDWARE_CNG, SOFTWARE
    // Signature over the enrollment transaction's nonce, using the private key
    // matching [publicKey] -- the actual proof-of-possession check (Section 4.2).
    @field:NotBlank val proofOfPossession: String, // base64 signature
    val fingerprintVersion: Int = 1,
    @field:NotBlank val fingerprintHash: String,
)

data class EnrollmentCompleteResponse(
    val deviceId: UUID,
    val status: String,
    val approvalType: String,
    val certificateStatus: String,
    val certificatePem: String? = null,
    val issuingCaPem: String? = null,
    val policyVersion: Int,
    val message: String,
)

// ---- Device inventory / detail (Admin Console, Section 13.2) ----

data class DeviceSummaryResponse(
    val id: UUID,
    val tenantId: UUID,
    val userId: UUID,
    val hostname: String?,
    val platform: String,
    val ownership: String,
    val lifecycleStatus: String,
    val agentVersion: String?,
    val lastSeenAt: Instant?,
    val postureStatus: String?,
    // The latest reported facts and the server's verdict on them -- see DevicePostureModels.kt. All null
    // until the agent's first posture report.
    val postureRiskScore: Int? = null,
    val postureEvaluatedAt: Instant? = null,
    val postureReasons: List<String> = emptyList(),
    val postureSignals: PostureSignals? = null,
    val certificateStatus: String?,
    val createdAt: Instant,
)

// ---- Approval actions (Section 6.3) ----

data class DeviceActionRequest(
    val reason: String? = null,
)

// ---- Heartbeat / posture / events / compliance (device-authenticated) ----

data class DeviceHeartbeatRequest(
    @field:NotBlank val agentVersion: String,
    @field:NotNull val policyVersion: Int,
    @field:NotBlank val healthStatus: String, // HEALTHY, DEGRADED, TAMPERED
)

// The agent reports facts only. It does not (and cannot) send a verdict: the server evaluates the signals
// against its own rules (PostureEvaluator), so a modified agent can't claim to be compliant.
data class DevicePostureRequest(
    @field:Valid @field:NotNull val signals: PostureSignals,
)

data class DeviceEventRequest(
    @field:NotBlank val eventType: String,
    @field:NotBlank @field:jakarta.validation.constraints.Pattern(regexp = "INFO|WARNING|CRITICAL") val severity: String,
    val metadataJson: String? = null,
)

// POST /devices/{id}/compliance (spec Section 10): same facts, same server-side evaluation as /posture.
data class DeviceComplianceRequest(
    @field:Valid @field:NotNull val signals: PostureSignals,
)

// ---- Signed policy fetch (Section 10.3) ----

data class DeviceAppPolicyResponse(
    val applicationId: UUID,
    val pendingAccess: Boolean,
    val offlineAccess: Boolean,
    val offlineGraceSeconds: Int,
    val failureMode: String,
)

data class DevicePolicyResponse(
    // Signed, and checked by the agent against its own identity -- a policy is only valid for the one
    // tenant/device it was issued to (spec Section 15.3 "tenant/device bound").
    val tenantId: UUID,
    val deviceId: UUID,
    val policyId: UUID,
    val policyVersion: Int,
    val issuedAt: Instant,
    val expiresAt: Instant,
    val deviceStatus: String,
    val heartbeatIntervalSeconds: Int,
    val postureIntervalSeconds: Int,
    val agentFailureMode: String,
    val applications: List<DeviceAppPolicyResponse>,
    // Detached signature over a canonical encoding of this response (minus
    // this field) -- see DevicePolicySigner. The agent must verify this
    // before trusting/caching the policy (Section 16 "Policy: signed,
    // versioned, expiring and rollback-protected").
    val signature: String,
)

// GET /devices/{id}/events -- the device's activity timeline in the Admin Console. Newest first.
data class DeviceEventResponse(
    val eventType: String,
    val severity: String,
    val metadataJson: String?,
    val occurredAt: Instant,
)
