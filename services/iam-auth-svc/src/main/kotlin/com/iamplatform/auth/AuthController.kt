package com.iamplatform.auth

import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.HttpClientErrorException

@RestController
@RequestMapping("/api/v1")
class AuthController(
    private val authService: AuthService,
    private val breakGlassService: BreakGlassService,
) {

    @PostMapping("/login")
    fun login(@Valid @RequestBody request: LoginRequest): ResponseEntity<LoginResponse> =
        ResponseEntity.ok(authService.login(request))

    // Added for iam-login-portal's multi-step wizard -- see AuthService.precheck.
    @PostMapping("/login/precheck")
    fun precheck(@Valid @RequestBody request: PrecheckRequest): ResponseEntity<PrecheckResponse> =
        ResponseEntity.ok(authService.precheck(request))

    @PostMapping("/logout")
    fun logout(@RequestHeader("X-Session-Token") token: String): ResponseEntity<Void> {
        try {
            authService.logout(token)
        } catch (ex: HttpClientErrorException.NotFound) {
            throw LogoutSessionNotFoundException()
        }
        return ResponseEntity.noContent().build()
    }

    // AP-8 break-glass path -- deliberately not session-gated (the whole
    // point is working with no valid session at all); gated instead by
    // possession of the per-tenant OpenBao-only token. See BreakGlassService
    // and BreakGlassTokenProvider. Not referenced from any UI.
    @PostMapping("/break-glass/reset-2fa")
    fun breakGlassResetTwoFactor(
        @Valid @RequestBody request: BreakGlassResetRequest,
        servletRequest: HttpServletRequest,
    ): ResponseEntity<BreakGlassResetResponse> =
        ResponseEntity.ok(breakGlassService.resetTwoFactor(request, servletRequest.remoteAddr))
}
