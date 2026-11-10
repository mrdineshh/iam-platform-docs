package com.iamplatform.tenant

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

data class DevicePostureRequest(
    @field:NotBlank val postureStatus: String, // COMPLIANT, NON_COMPLIANT, UNKNOWN
    val riskScore: Int? = null,
    val signalsJson: String? = null,
)

data class DeviceEventRequest(
    @field:NotBlank val eventType: String,
    @field:NotBlank val severity: String, // INFO, WARNING, CRITICAL
    val metadataJson: String? = null,
)

data class DeviceComplianceRequest(
    @field:NotBlank val postureStatus: String,
    val signalsJson: String? = null,
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
