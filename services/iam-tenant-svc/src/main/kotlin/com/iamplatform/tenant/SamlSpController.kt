package com.iamplatform.tenant

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
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

@RestController
@RequestMapping("/api/v1/saml-sps")
class SamlSpController(
    private val service: SamlSpService,
    private val adminAccessGuard: AdminAccessGuard,
) {

    @PostMapping
    fun createSamlSp(
        @Valid @RequestBody request: CreateSamlSpRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<SamlSpResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, request.tenantId)
        return ResponseEntity.status(HttpStatus.CREATED).body(service.createSamlSp(request).toResponse())
    }

    @GetMapping
    fun listSamlSps(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<SamlSpResponse>> {
        val session = adminAccessGuard.requireValidSession(sessionToken)
        if (session.tenantId != tenantId) {
            throw AdminAccessDeniedException("session does not belong to this tenant")
        }
        return ResponseEntity.ok(service.listSamlSps(tenantId).map { it.toResponse() })
    }

    @GetMapping("/{id}")
    fun getSamlSp(@PathVariable id: UUID): ResponseEntity<SamlSpResponse> =
        ResponseEntity.ok(service.getSamlSp(id).toResponse())

    // Internal -- iam-oidcprovider-svc resolves an incoming AuthnRequest's
    // Issuer to a registered SP. Unauthenticated at this layer, same as
    // OidcClientController.getClient (mTLS-only inbound network).
    @GetMapping("/by-entity-id")
    fun findBySpEntityId(@RequestParam entityId: String): ResponseEntity<SamlSpResponse> {
        val sp = service.findBySpEntityId(entityId) ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok(sp.toResponse())
    }

    // Group-based launchpad visibility -- same pattern and reasoning as
    // OidcClientController's /groups endpoints.
    @PutMapping("/{id}/groups")
    fun setGroups(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @Valid @RequestBody request: UpdateAppGroupsRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<AppGroupsResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        service.setGroups(id, request.groupIds)
        return ResponseEntity.ok(AppGroupsResponse(request.groupIds))
    }

    @GetMapping("/{id}/groups")
    fun getGroups(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<AppGroupsResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(AppGroupsResponse(service.getGroupIds(id)))
    }
}
