package com.iamplatform.tenant

import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant
import java.util.UUID

/**
 * Backend API for the Endpoint Device Trust agent (spec Section 10),
 * Windows-only in Phase 1. Two distinct caller identities use this
 * controller:
 *  - The signed-in IAM user / admin console, authenticated the same way as
 *    every other admin-gated endpoint in this service (X-Session-Token,
 *    see AdminAccessGuard) -- enrollment/start, device inventory, and the
 *    approve/reject/suspend/revoke actions.
 *  - The enrolled agent itself, authenticated by a signed challenge over
 *    its own device id instead of a session token (see
 *    DeviceTrustService.requireDeviceProof) -- heartbeat, posture, events,
 *    compliance and policy fetch. enrollment/complete is the one
 *    exception: the device isn't registered yet, so it authenticates
 *    solely via the one-time enrollment transaction plus proof-of-possession
 *    of the key it's registering.
 */
@RestController
@RequestMapping("/api/v1/endpoint")
class DeviceController(
    private val deviceTrustService: DeviceTrustService,
    private val adminAccessGuard: AdminAccessGuard,
) {
    // Called server-to-server by iam-login-portal's /device-enroll route, using the browser's SSO
    // session -- the agent itself never holds a session token, only the transaction this returns.
    @PostMapping("/enrollment/start")
    fun startEnrollment(
        @Valid @RequestBody request: EnrollmentStartRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<EnrollmentStartResponse> {
        val session = adminAccessGuard.requireValidSession(sessionToken)
        return ResponseEntity.ok(deviceTrustService.startEnrollment(session.tenantId, session.userId, request.keyThumbprint))
    }

    @PostMapping("/enrollment/complete")
    fun completeEnrollment(
        @Valid @RequestBody request: EnrollmentCompleteRequest,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<EnrollmentCompleteResponse> =
        ResponseEntity.status(HttpStatus.CREATED).body(deviceTrustService.completeEnrollment(request, httpRequest.remoteAddr))

    @GetMapping("/devices")
    fun listDevices(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<DeviceSummaryResponse>> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(deviceTrustService.listDevices(tenantId))
    }

    @GetMapping("/devices/{deviceId}")
    fun getDevice(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<DeviceSummaryResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(deviceTrustService.getDevice(tenantId, deviceId))
    }

    @PostMapping("/devices/{deviceId}/approve")
    fun approve(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @RequestBody(required = false) request: DeviceActionRequest?,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<Void> {
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        deviceTrustService.approve(tenantId, deviceId, admin.userId.toString(), request?.reason, httpRequest.remoteAddr)
        return ResponseEntity.noContent().build()
    }

    @PostMapping("/devices/{deviceId}/reject")
    fun reject(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @RequestBody(required = false) request: DeviceActionRequest?,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<Void> {
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        deviceTrustService.reject(tenantId, deviceId, admin.userId.toString(), request?.reason, httpRequest.remoteAddr)
        return ResponseEntity.noContent().build()
    }

    @PostMapping("/devices/{deviceId}/suspend")
    fun suspend(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @RequestBody(required = false) request: DeviceActionRequest?,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<Void> {
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        deviceTrustService.suspend(tenantId, deviceId, admin.userId.toString(), request?.reason, httpRequest.remoteAddr)
        return ResponseEntity.noContent().build()
    }

    @PostMapping("/devices/{deviceId}/revoke")
    fun revoke(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @RequestBody(required = false) request: DeviceActionRequest?,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<Void> {
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        deviceTrustService.revoke(tenantId, deviceId, admin.userId.toString(), request?.reason, httpRequest.remoteAddr)
        return ResponseEntity.noContent().build()
    }

    @PostMapping("/devices/{deviceId}/heartbeat")
    fun heartbeat(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @Valid @RequestBody request: DeviceHeartbeatRequest,
        @RequestHeader("X-Device-Signature") signature: String,
        @RequestHeader("X-Device-Timestamp") timestamp: String,
    ): ResponseEntity<Void> {
        deviceTrustService.requireDeviceProof(tenantId, deviceId, parseTimestamp(timestamp), signature)
        deviceTrustService.heartbeat(tenantId, deviceId, request)
        return ResponseEntity.noContent().build()
    }

    @PatchMapping("/devices/{deviceId}/posture")
    fun updatePosture(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @Valid @RequestBody request: DevicePostureRequest,
        @RequestHeader("X-Device-Signature") signature: String,
        @RequestHeader("X-Device-Timestamp") timestamp: String,
    ): ResponseEntity<Void> {
        deviceTrustService.requireDeviceProof(tenantId, deviceId, parseTimestamp(timestamp), signature)
        deviceTrustService.updatePosture(tenantId, deviceId, request)
        return ResponseEntity.noContent().build()
    }

    @PostMapping("/devices/{deviceId}/events")
    fun recordEvent(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @Valid @RequestBody request: DeviceEventRequest,
        @RequestHeader("X-Device-Signature") signature: String,
        @RequestHeader("X-Device-Timestamp") timestamp: String,
    ): ResponseEntity<Void> {
        deviceTrustService.requireDeviceProof(tenantId, deviceId, parseTimestamp(timestamp), signature)
        deviceTrustService.recordEvent(tenantId, deviceId, request)
        return ResponseEntity.noContent().build()
    }

    @PostMapping("/devices/{deviceId}/compliance")
    fun recordCompliance(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @Valid @RequestBody request: DeviceComplianceRequest,
        @RequestHeader("X-Device-Signature") signature: String,
        @RequestHeader("X-Device-Timestamp") timestamp: String,
    ): ResponseEntity<Void> {
        deviceTrustService.requireDeviceProof(tenantId, deviceId, parseTimestamp(timestamp), signature)
        deviceTrustService.recordCompliance(tenantId, deviceId, request)
        return ResponseEntity.noContent().build()
    }

    @GetMapping("/devices/{deviceId}/policy")
    fun fetchPolicy(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Device-Signature") signature: String,
        @RequestHeader("X-Device-Timestamp") timestamp: String,
    ): ResponseEntity<DevicePolicyResponse> {
        deviceTrustService.requireDeviceProof(tenantId, deviceId, parseTimestamp(timestamp), signature)
        return ResponseEntity.ok(deviceTrustService.fetchPolicy(tenantId, deviceId))
    }

    // Bound as a plain String, not Instant, and parsed explicitly here -- Spring's implicit
    // String->Instant @RequestHeader conversion depends on formatter registration that isn't
    // guaranteed across Boot versions; ISO-8601 (Instant.parse) is also exactly what the Rust
    // agent's chrono::DateTime<Utc>::to_rfc3339() / serde_json serialization produces by default.
    private fun parseTimestamp(value: String): Instant =
        try {
            Instant.parse(value)
        } catch (ex: Exception) {
            throw DeviceProofOfPossessionException("Malformed X-Device-Timestamp header")
        }
}
