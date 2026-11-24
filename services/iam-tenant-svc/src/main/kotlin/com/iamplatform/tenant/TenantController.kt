package com.iamplatform.tenant

import jakarta.validation.Valid
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/api/v1/tenants")
class TenantController(
    private val tenantService: TenantService,
    private val brandingService: TenantBrandingService,
    private val adminAccessGuard: AdminAccessGuard,
    // The platform operator's own tenant. Only its administrators may onboard other organizations.
    @Value("\${iam.platform.operator-subdomain:econz}") private val operatorSubdomain: String,
) {

    @PostMapping
    fun createTenant(
        @Valid @RequestBody request: CreateTenantRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<TenantResponse> {
        requireOperatorAdmin(sessionToken)
        return ResponseEntity.status(HttpStatus.CREATED).body(tenantService.createTenant(request).toResponse())
    }

    /** Lets the console decide whether to show the onboarding screen. Never an error: anything but a platform admin is just false. */
    @GetMapping("/can-onboard")
    fun canOnboard(@RequestHeader("X-Session-Token") sessionToken: String): ResponseEntity<CanOnboardResponse> =
        ResponseEntity.ok(CanOnboardResponse(runCatching { requireOperatorAdmin(sessionToken) }.isSuccess))

    private fun requireOperatorAdmin(sessionToken: String) {
        adminAccessGuard.requireValidSession(sessionToken)
        val operator = runCatching { tenantService.getTenantBySubdomain(operatorSubdomain) }.getOrNull()
            ?: throw AdminAccessDeniedException("Only the platform operator can onboard an organization.")
        try {
            adminAccessGuard.requireTenantAdmin(sessionToken, operator.id)
        } catch (ex: AdminAccessDeniedException) {
            throw AdminAccessDeniedException("Only the platform operator can onboard an organization.")
        }
    }

    @GetMapping("/{id}")
    fun getTenant(@PathVariable id: UUID): ResponseEntity<TenantResponse> =
        ResponseEntity.ok(tenantService.getTenant(id).let { it.toResponse(brandingService.find(it.id)?.toResponse()) })

    // Added for Service 13 (iam-login-portal) -- resolves tenantId from the
    // Host header subdomain per FR-6.2. See docs/specs/iam-login-portal-SPEC.md
    // Section 1.2.
    @GetMapping("/by-subdomain/{subdomain}")
    fun getTenantBySubdomain(@PathVariable subdomain: String): ResponseEntity<TenantResponse> =
        ResponseEntity.ok(
            tenantService.getTenantBySubdomain(subdomain).let { it.toResponse(brandingService.find(it.id)?.toResponse()) },
        )
}

data class CanOnboardResponse(val allowed: Boolean)
