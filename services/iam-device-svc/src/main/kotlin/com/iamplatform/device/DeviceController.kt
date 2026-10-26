package com.iamplatform.device

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/devices")
class DeviceController(
    private val deviceService: DeviceService,
) {

    @PostMapping("/enroll")
    fun enroll(@Valid @RequestBody request: EnrollDeviceRequest): ResponseEntity<EnrollDeviceResponse> =
        ResponseEntity.status(HttpStatus.CREATED).body(deviceService.enroll(request))

    // Added for self-service first-login enrollment (iam-auth-svc only).
    @PostMapping("/ensure-pending")
    fun ensurePending(@Valid @RequestBody request: EnsurePendingRequest): ResponseEntity<EnsurePendingResponse> =
        ResponseEntity.ok(deviceService.ensurePending(request))

    // Added for the totpReenrollEveryLogin policy (iam-auth-svc only).
    @PostMapping("/reset-and-enroll")
    fun resetAndEnroll(@Valid @RequestBody request: ResetAndEnrollRequest): ResponseEntity<ResetAndEnrollResponse> =
        ResponseEntity.ok(deviceService.resetAndEnroll(request))

    @PostMapping("/totp/verify")
    fun verifyTotp(@Valid @RequestBody request: TotpVerifyRequest): ResponseEntity<TotpVerifyResponse> =
        ResponseEntity.ok(deviceService.verifyTotp(request))

    @PostMapping("/push/send")
    fun sendPush(@Valid @RequestBody request: PushSendRequest): ResponseEntity<PushSendResponse> =
        ResponseEntity.ok(deviceService.sendPush(request))

    @PostMapping("/push/respond")
    fun respondToPush(@Valid @RequestBody request: PushRespondRequest): ResponseEntity<Void> {
        deviceService.respondToPush(request)
        return ResponseEntity.noContent().build()
    }
}
