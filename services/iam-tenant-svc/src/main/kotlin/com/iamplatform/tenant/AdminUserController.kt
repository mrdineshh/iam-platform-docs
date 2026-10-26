package com.iamplatform.tenant

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

/**
 * Admin-console "create user" self-service page. Admin-gated (same
 * AdminAccessGuard every other Service-14 endpoint uses) -- proxies to
 * iam-identity-svc, which is mTLS-only inbound and so can't be called
 * directly from the browser SPA.
 *
 * Also enrolls the new user's first 2FA device in the same call. This
 * isn't optional: iam-auth-svc requires a second factor on every login,
 * unconditionally, with no first-login grace period (see AuthService.kt's
 * own comment -- deliberate MVP scope, not a bug). A brand-new user with
 * zero devices literally cannot log in, and self-service enrollment
 * (SelfServiceController) requires a session they can't get without
 * logging in first -- a real chicken-and-egg gap. Bootstrapping the first
 * device here, admin-mediated, mirrors how enterprise IT onboarding
 * actually works (the admin hands the QR to the new hire directly); the
 * self-service page still covers everything after that first device.
 */
@RestController
@RequestMapping("/api/v1/admin/users")
class AdminUserController(
    private val identityClient: IdentityClient,
    private val deviceClient: DeviceClient,
    private val adminAccessGuard: AdminAccessGuard,
) {
    @PostMapping
    fun createUser(
        @Valid @RequestBody request: CreateUserRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<CreatedUserResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, request.tenantId)
        val created = identityClient.createUser(
            CreateRemoteUserRequest(
                tenantId = request.tenantId,
                email = request.email,
                displayName = request.displayName,
                password = request.password,
                role = request.role,
            ),
        )
        val device = deviceClient.enroll(created.tenantId, created.id)
        return ResponseEntity.status(HttpStatus.CREATED).body(
            CreatedUserResponse(
                id = created.id,
                tenantId = created.tenantId,
                email = created.email,
                displayName = created.displayName,
                role = created.role,
                totpSecret = device.totpSecret,
                provisioningUri = device.provisioningUri,
            ),
        )
    }
}
