package com.iamplatform.tenant

import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

/**
 * Admin API for SCIM provisioning connections: which connected apps receive
 * user lifecycle changes, where, and with what token. Admin-gated like every
 * other tenant-settings endpoint. The bearer token is write-only here; it is
 * stored in OpenBao and never returned.
 */
@RestController
@RequestMapping("/api/v1/admin/provisioning/connections")
class ProvisioningController(
    private val service: ScimConnectionService,
    private val adminAccessGuard: AdminAccessGuard,
) {
    @GetMapping
    fun list(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<ScimConnectionView>> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(service.list(tenantId))
    }

    @PutMapping
    fun upsert(
        @Valid @RequestBody request: UpsertScimConnectionRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<ScimConnectionView> {
        adminAccessGuard.requireTenantAdmin(sessionToken, request.tenantId)
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        return ResponseEntity.ok(service.upsert(request, admin.userId))
    }

    @DeleteMapping("/{id}")
    fun delete(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<Void> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        service.delete(tenantId, id, adminAccessGuard.requireValidSession(sessionToken).userId)
        return ResponseEntity.noContent().build()
    }

    @PostMapping("/{id}/test")
    fun test(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<ConnectionTestResult> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(service.test(tenantId, id))
    }

    // Pushes every existing user to a newly connected app (or re-pushes after a fix).
    @PostMapping("/{id}/sync")
    fun sync(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<SyncSummary> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(service.sync(tenantId, id, adminAccessGuard.requireValidSession(sessionToken).userId))
    }
}
