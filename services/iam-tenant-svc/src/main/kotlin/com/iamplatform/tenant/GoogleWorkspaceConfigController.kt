package com.iamplatform.tenant

import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import org.springframework.http.ResponseEntity
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

data class SyncOrgUnitRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    val orgUnitPath: String,
)

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
    private val reportService: GoogleWorkspaceDirectoryReportService,
    private val ouProvisioningService: GoogleWorkspaceOuProvisioningService,
    private val groupPushService: GoogleWorkspaceGroupPushService,
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

    // Read-only report -- see GoogleWorkspaceDirectoryReportService's doc comment. Changes nothing
    // in Google or in IAM; safe to call as often as the admin console wants to refresh the view.
    @GetMapping("/organizational-units")
    fun organizationalUnits(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<OrgUnitReport>> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(reportService.listByOrgUnit(tenantId))
    }

    // Writes -- see GoogleWorkspaceOuProvisioningService's doc comment. Scoped to exactly one OU per
    // call, by deliberate design (the explicit ask behind this feature was "only Ratnesh Test").
    @PostMapping("/organizational-units/sync")
    fun syncOrgUnit(
        @Valid @RequestBody request: SyncOrgUnitRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<OuProvisionResult> {
        adminAccessGuard.requireTenantAdmin(sessionToken, request.tenantId)
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        return ResponseEntity.ok(ouProvisioningService.syncOrgUnit(request.tenantId, request.orgUnitPath, admin.userId, httpRequest.remoteAddr))
    }

    // The reverse direction -- see GoogleWorkspaceGroupPushService's doc comment. One IAM group pushed
    // into Google as an OU, moving its current members in; never creates a Google account, never
    // removes anyone from the OU later just because they left the group.
    @PostMapping("/groups/{groupId}/push-to-org-unit")
    fun pushGroupToOrgUnit(
        @PathVariable groupId: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<GroupPushResult> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        return ResponseEntity.ok(groupPushService.pushGroupToOrgUnit(tenantId, groupId, admin.userId, httpRequest.remoteAddr))
    }
}
