package com.iamplatform.tenant

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

data class DeviceTrustStatusResponse(val deviceId: UUID, val tenantId: UUID, val lifecycleStatus: String)

/**
 * Not part of the admin-console contract -- only iam-enforcement-svc's PEP
 * calls this, to confirm a session's claimed device is still APPROVED on
 * every request (Endpoint Device Trust spec Section 4, AP-2 "killable
 * mid-flight"). Same "/internal/..." no-session-token, mTLS-trusted-caller
 * pattern as iam-oidcprovider-svc's InternalController -- deliberately
 * exposes nothing beyond the one field the PEP actually needs to decide.
 */
@RestController
class InternalDeviceController(
    private val deviceTrustService: DeviceTrustService,
) {
    @GetMapping("/internal/devices/{deviceId}")
    fun trustStatus(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
    ): ResponseEntity<DeviceTrustStatusResponse> {
        val device = deviceTrustService.getDevice(tenantId, deviceId)
        return ResponseEntity.ok(DeviceTrustStatusResponse(device.id, device.tenantId, device.lifecycleStatus))
    }
}
