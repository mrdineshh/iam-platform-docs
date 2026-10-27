package com.iamplatform.tenant

import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

data class AppAccessResponse(val allowed: Boolean, val reason: String? = null)

/**
 * Whether a user may sign in to a connected app. Same rule as the "My Apps"
 * launchpad (MyAppsController): an ADMIN may open every app of their tenant;
 * anyone else only apps assigned to their own group; a user with no group, or
 * an app with no groups, means no access. Kept in one place so "what you see"
 * and "what you can sign in to" can never disagree.
 */
@Service
class AppAccessService(
    private val oidcClients: OidcClientRepository,
    private val samlSps: SamlSpRepository,
    private val oidcClientGroups: OidcClientGroupRepository,
    private val samlSpGroups: SamlSpGroupRepository,
) {
    fun check(sessionTenantId: UUID, role: RemoteUserRole, groupId: UUID?, appKind: String, appId: UUID): AppAccessResponse {
        val kind = appKind.lowercase()
        val appTenantId = when (kind) {
            "oidc" -> oidcClients.findById(appId).map { it.tenantId }.orElse(null)
            "saml" -> samlSps.findById(appId).map { it.tenantId }.orElse(null)
            else -> return AppAccessResponse(false, "unknown app type")
        } ?: return AppAccessResponse(false, "app not found")

        if (appTenantId != sessionTenantId) return AppAccessResponse(false, "app belongs to another organization")
        if (role == RemoteUserRole.ADMIN) return AppAccessResponse(true)
        if (groupId == null) return AppAccessResponse(false, "you are not in a group that has access to this app")

        val allowedGroups = when (kind) {
            "oidc" -> oidcClientGroups.findByOidcClientId(appId).map { it.groupId }
            else -> samlSpGroups.findBySamlSpId(appId).map { it.groupId }
        }
        return if (groupId in allowedGroups) {
            AppAccessResponse(true)
        } else {
            AppAccessResponse(false, "your group does not have access to this app")
        }
    }
}

/**
 * Called by iam-oidcprovider-svc just before it completes an app sign-in (OIDC
 * code or SAML assertion). Authenticated by the user's own session token: the
 * user and tenant come from the session, never from a parameter, so this can't
 * be used to look up anyone else's access.
 */
@RestController
@RequestMapping("/api/v1/app-access")
class AppAccessController(
    private val adminAccessGuard: AdminAccessGuard,
    private val identityClient: IdentityClient,
    private val appAccessService: AppAccessService,
) {
    @GetMapping
    fun check(
        @RequestParam appKind: String,
        @RequestParam appId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<AppAccessResponse> {
        val session = adminAccessGuard.requireValidSession(sessionToken)
        val user = identityClient.findUser(session.userId)
            ?: return ResponseEntity.ok(AppAccessResponse(false, "user no longer exists"))
        return ResponseEntity.ok(appAccessService.check(session.tenantId, user.role, user.groupId, appKind, appId))
    }
}
