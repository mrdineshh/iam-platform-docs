package com.iamplatform.auth

import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

/**
 * The sign-in used to register a new laptop. Identical to /api/v1/login (same password, policy and second-factor checks,
 * same engine -- AP-1) except that the tenant's "authorised laptop to sign in" rule is not applied, because the laptop does
 * not exist yet. Service-to-service only (InternalOnlyFilter); the portal uses the session it returns solely to start the
 * enrollment and then ends it, and never gives it to the browser.
 */
@RestController
@RequestMapping("/internal/login")
class InternalLoginController(private val authService: AuthService) {

    // The password step of the same sign-in: also exempt from the rule, for the same reason, and just as closed to the internet.
    @PostMapping("/precheck-enrollment")
    fun enrollmentPrecheck(@Valid @RequestBody request: PrecheckRequest, servletRequest: HttpServletRequest): ResponseEntity<PrecheckResponse> {
        val (ip, userAgent) = ClientContext.resolve(servletRequest, request.sourceIp, request.userAgent)
        return ResponseEntity.ok(authService.precheck(request.copy(sourceIp = ip, userAgent = userAgent), enforceDeviceRule = false))
    }

    @PostMapping("/enrollment")
    fun enrollmentLogin(@Valid @RequestBody request: LoginRequest, servletRequest: HttpServletRequest): ResponseEntity<LoginResponse> {
        val (ip, userAgent) = ClientContext.resolve(servletRequest, request.sourceIp, request.userAgent)
        return ResponseEntity.ok(authService.login(request.copy(sourceIp = ip, userAgent = userAgent), enforceDeviceRule = false))
    }
}
