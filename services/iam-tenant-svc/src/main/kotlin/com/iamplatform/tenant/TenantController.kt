package com.iamplatform.tenant

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/api/v1/tenants")
class TenantController(
    private val tenantService: TenantService,
    private val brandingService: TenantBrandingService,
) {

    @PostMapping
    fun createTenant(@Valid @RequestBody request: CreateTenantRequest): ResponseEntity<TenantResponse> =
        ResponseEntity.status(HttpStatus.CREATED).body(tenantService.createTenant(request).toResponse())

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
