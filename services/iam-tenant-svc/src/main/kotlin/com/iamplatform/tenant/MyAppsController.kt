package com.iamplatform.tenant

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

data class MyAppTile(val id: UUID, val name: String, val launchUrl: String, val type: String)

/**
 * The single merged, group-filtered source of truth for "My Apps" tiles --
 * both iam-login-portal's /apps page and iam-admin-console's LaunchpadPage
 * call this instead of separately fetching+merging the raw OIDC/SAML lists
 * themselves (added 2026-10-23, group-based app access). Session-gated
 * only, like the underlying list endpoints -- any logged-in user can see
 * their own launchpad.
 *
 * Visibility rule: an ADMIN sees every connected app with a launch URL,
 * unconditionally -- group restriction is a launchpad convenience for
 * regular users, not a management boundary, and admins already manage
 * every app from the Connected Apps page regardless of group. A non-admin
 * user sees only apps assigned to their own group (iam-identity-svc's
 * single-group-per-user shape); a user with no group sees nothing, which
 * is deliberate -- an app with no group assignment at all is likewise
 * invisible to everyone but admins, so "no group" and "app unassigned" are
 * the same hidden-by-default state, not a special case.
 */
@RestController
@RequestMapping("/api/v1/my-apps")
class MyAppsController(
    private val oidcClientService: OidcClientService,
    private val samlSpService: SamlSpService,
    private val identityClient: IdentityClient,
    private val adminAccessGuard: AdminAccessGuard,
) {
    @GetMapping
    fun myApps(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<MyAppTile>> {
        val session = adminAccessGuard.requireValidSession(sessionToken)
        if (session.tenantId != tenantId) {
            throw AdminAccessDeniedException("session does not belong to this tenant")
        }
        val user = identityClient.findUser(session.userId)
            ?: throw AdminAccessDeniedException("user for this session no longer exists")

        val (clients, sps) = if (user.role == RemoteUserRole.ADMIN) {
            oidcClientService.listClients(tenantId) to samlSpService.listSamlSps(tenantId)
        } else {
            val groupId = user.groupId
            if (groupId == null) {
                emptyList<OidcClientEntity>() to emptyList<SamlSpEntity>()
            } else {
                oidcClientService.listClientsForGroup(groupId) to samlSpService.listSamlSpsForGroup(groupId)
            }
        }

        val tiles = clients.filter { !it.launchUrl.isNullOrBlank() }.map { MyAppTile(it.id, it.name, it.launchUrl!!, "OIDC") } +
            sps.filter { !it.launchUrl.isNullOrBlank() }.map { MyAppTile(it.id, it.name, it.launchUrl!!, "SAML") }

        return ResponseEntity.ok(tiles)
    }
}
