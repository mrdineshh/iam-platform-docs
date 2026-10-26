package com.iamplatform.tenant

import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Self-service 2FA enrollment ("My Security" page) -- session-gated only
 * (AdminAccessGuard.requireValidSession, not requireTenantAdmin), since any
 * authenticated user enrolls their own device, not an org-wide admin
 * action. The raw TOTP secret/provisioningUri only ever reaches the caller
 * who owns the session it was issued to -- never logged, never shown to an
 * admin, matching device-svc's own "shown once" contract.
 */
@RestController
@RequestMapping("/api/v1/me/2fa")
class SelfServiceController(
    private val deviceClient: DeviceClient,
    private val adminAccessGuard: AdminAccessGuard,
) {
    @PostMapping("/enroll")
    fun enroll(@RequestHeader("X-Session-Token") sessionToken: String): ResponseEntity<Enroll2faResponse> {
        val session = adminAccessGuard.requireValidSession(sessionToken)
        val enrolled = deviceClient.enroll(session.tenantId, session.userId)
        return ResponseEntity.ok(
            Enroll2faResponse(enrolled.deviceId, enrolled.status, enrolled.totpSecret, enrolled.provisioningUri),
        )
    }

    @PostMapping("/verify")
    fun verify(
        @Valid @RequestBody request: Verify2faRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<Verify2faResponse> {
        val session = adminAccessGuard.requireValidSession(sessionToken)
        val result = deviceClient.verifyTotp(session.tenantId, session.userId, request.code)
        return ResponseEntity.ok(Verify2faResponse(result.valid, result.status))
    }
}
