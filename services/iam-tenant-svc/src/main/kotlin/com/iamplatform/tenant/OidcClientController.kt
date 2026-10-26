package com.iamplatform.tenant

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/api/v1/oidc-clients")
class OidcClientController(
    private val service: OidcClientService,
    private val adminAccessGuard: AdminAccessGuard,
) {

    @PostMapping
    fun createClient(@Valid @RequestBody request: CreateOidcClientRequest): ResponseEntity<CreatedOidcClientResponse> {
        val (client, secret) = service.createClient(request)
        return ResponseEntity.status(HttpStatus.CREATED).body(
            CreatedOidcClientResponse(
                clientId = client.id,
                clientSecret = secret,
                tenantId = client.tenantId,
                name = client.name,
                redirectUris = client.redirectUriList,
                launchUrl = client.launchUrl,
                createdAt = client.createdAt,
            ),
        )
    }

    @GetMapping("/{id}")
    fun getClient(@PathVariable id: UUID): ResponseEntity<OidcClientResponse> =
        ResponseEntity.ok(service.getClient(id).toResponse())

    // Added for Service 14 (iam-admin-console). Session-gated only, not
    // admin-only -- the app launchpad (any logged-in user, not just
    // admins) needs this same list to render tiles, and nothing sensitive
    // is exposed here (no client_secret; that's only ever returned once,
    // at creation). Loosened from requireTenantAdmin for that reason.
    @GetMapping
    fun listClients(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<OidcClientResponse>> {
        val session = adminAccessGuard.requireValidSession(sessionToken)
        if (session.tenantId != tenantId) {
            throw AdminAccessDeniedException("session does not belong to this tenant")
        }
        return ResponseEntity.ok(service.listClients(tenantId).map { it.toResponse() })
    }

    @PostMapping("/{id}/verify-secret")
    fun verifySecret(
        @PathVariable id: UUID,
        @Valid @RequestBody request: VerifyClientSecretRequest,
    ): ResponseEntity<VerifyClientSecretResponse> =
        ResponseEntity.ok(service.verifySecret(id, request))

    // Added for group-based launchpad visibility (2026-10-23). Admin-gated
    // like every other app-management endpoint -- deciding who can launch
    // an app is a management action, not something any logged-in user
    // should be able to change about themselves.
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
