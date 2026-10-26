package com.iamplatform.tenant

import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

data class CreateGroupAdminRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    val name: String,
)

data class AssignGroupAdminRequest(
    val groupId: UUID? = null,
)

/**
 * Admin-console "Groups" page -- a group IS an OU for policy purposes
 * (iam-policy-svc's PolicyScope.OU), so a group's 2FA requirement / IP
 * allowlist is configured through the existing PUT /api/v1/policies
 * endpoint with scope=OU, scopeId=<groupId> -- no new policy plumbing
 * needed, just this group CRUD + membership layer in front of
 * iam-identity-svc (mTLS-only inbound, admin-gated here same as every
 * other endpoint in this file's siblings).
 */
@RestController
@RequestMapping("/api/v1/admin/groups")
class GroupController(
    private val groupClient: GroupClient,
    private val adminAccessGuard: AdminAccessGuard,
    private val oidcClientGroupRepository: OidcClientGroupRepository,
    private val samlSpGroupRepository: SamlSpGroupRepository,
) {
    @PostMapping
    fun createGroup(
        @Valid @RequestBody request: CreateGroupAdminRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<RemoteGroup> {
        adminAccessGuard.requireTenantAdmin(sessionToken, request.tenantId)
        return ResponseEntity.status(HttpStatus.CREATED).body(groupClient.createGroup(request.tenantId, request.name))
    }

    @GetMapping
    fun listGroups(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<RemoteGroup>> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(groupClient.listGroups(tenantId))
    }

    @PatchMapping("/members/{userId}")
    fun assignGroup(
        @PathVariable userId: UUID,
        @RequestParam tenantId: UUID,
        @Valid @RequestBody request: AssignGroupAdminRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<RemoteUser> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(groupClient.assignGroup(userId, request.groupId))
    }

    // Also drops this group's oidc_client_groups / saml_sp_groups rows --
    // those live in this service's own tenant_db, so iam-identity-svc's
    // deleteGroup (which only unassigns members) can't reach them.
    @DeleteMapping("/{id}")
    fun deleteGroup(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<Void> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        groupClient.deleteGroup(id)
        oidcClientGroupRepository.deleteByGroupId(id)
        samlSpGroupRepository.deleteByGroupId(id)
        return ResponseEntity.noContent().build()
    }
}
