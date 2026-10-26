package com.iamplatform.tenant

import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

/**
 * Admin-console "Google Workspace integration" settings -- where an admin
 * pastes the one-time service account JSON key (see
 * GoogleWorkspaceDirectoryClient's doc comment for the Google-side setup
 * that has to happen before this is usable). Admin-gated like every other
 * tenant-settings endpoint.
 */
@RestController
@RequestMapping("/api/v1/google-workspace-config")
class GoogleWorkspaceConfigController(
    private val service: GoogleWorkspaceConfigService,
    private val adminAccessGuard: AdminAccessGuard,
) {
    @PutMapping
    fun setConfig(
        @Valid @RequestBody request: SetGoogleWorkspaceConfigRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<GoogleWorkspaceConfigResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, request.tenantId)
        return ResponseEntity.ok(service.setConfig(request).toResponse())
    }

    @GetMapping
    fun getConfig(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<GoogleWorkspaceConfigResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        val config = service.getConfig(tenantId) ?: throw GoogleWorkspaceConfigNotFoundException(tenantId)
        return ResponseEntity.ok(config.toResponse())
    }
}
