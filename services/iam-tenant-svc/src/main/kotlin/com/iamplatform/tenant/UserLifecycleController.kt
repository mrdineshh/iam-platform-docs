package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

class CannotSuspendSelfException : RuntimeException("You can't suspend your own account.")

data class LifecycleResponse(
    val userId: UUID,
    val status: String,
    val sessionsEnded: Int,
    // One entry per downstream target (Google Workspace and each SCIM app).
    val targets: List<TargetResult>,
)

/**
 * Suspend and reactivate a user, and propagate the change to integrated apps.
 *
 * Suspending, in order: mark the user SUSPENDED in iam-identity-svc (so they
 * can no longer sign in and iam-enforcement-svc blocks their next request),
 * end every live session now (so a suspended user is signed out immediately
 * rather than at expiry), then suspend them in Google Workspace and in every
 * SCIM-connected app. Reactivating reverses the status and the downstream
 * accounts. Downstream failures never undo the platform-side change; they are
 * returned per target so the admin sees them and can retry.
 */
@RestController
@RequestMapping("/api/v1/admin/users")
class UserLifecycleController(
    private val identityClient: IdentityClient,
    private val sessionClient: SessionClient,
    private val adminAccessGuard: AdminAccessGuard,
    private val googleWorkspaceConfigService: GoogleWorkspaceConfigService,
    private val googleWorkspaceDirectoryClient: GoogleWorkspaceDirectoryClient,
    private val provisioningService: ProvisioningService,
    private val scimConnectionService: ScimConnectionService,
    private val auditPublisher: AuditPublisher,
) {
    @PostMapping("/{id}/suspend")
    fun suspend(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<LifecycleResponse> = ResponseEntity.ok(change(id, tenantId, sessionToken, httpRequest, suspend = true))

    @PostMapping("/{id}/reactivate")
    fun reactivate(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<LifecycleResponse> = ResponseEntity.ok(change(id, tenantId, sessionToken, httpRequest, suspend = false))

    // Where each integrated app stands for one user, with the last error if a push failed.
    @GetMapping("/{id}/provisioning")
    fun provisioningStatus(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<UserProvisioningStatus>> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        requireUserInTenant(id, tenantId)
        return ResponseEntity.ok(scimConnectionService.statusForUser(tenantId, id))
    }

    // Re-runs provisioning for this user so the apps match their current status. Safe to repeat.
    @PostMapping("/{id}/provisioning/retry")
    fun retry(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<TargetResult>> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        val user = requireUserInTenant(id, tenantId)
        val active = user.status != RemoteUserStatus.SUSPENDED
        val results = provisioningService.reconcile(
            ProvisionUser(id, tenantId, user.email ?: "", user.displayName ?: "", active),
        )
        return ResponseEntity.ok(results)
    }

    private fun change(id: UUID, tenantId: UUID, sessionToken: String, httpRequest: HttpServletRequest, suspend: Boolean): LifecycleResponse {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        val user = requireUserInTenant(id, tenantId)
        // An admin suspending themselves would lock the tenant out of the console.
        if (suspend && admin.userId == id) throw CannotSuspendSelfException()

        identityClient.updateStatus(id, if (suspend) RemoteUserStatus.SUSPENDED else RemoteUserStatus.ACTIVE)

        // Signed out now, not at expiry: a suspended user must not keep using what they already have.
        var sessionsEnded = 0
        if (suspend) {
            sessionsEnded = sessionClient.listForUser(tenantId, id).size
            sessionClient.terminateAllForUser(tenantId, id, "suspended-by-admin-${admin.userId}")
        }

        val targets = mutableListOf<TargetResult>()
        targets += googleTarget(tenantId, user, suspend)
        targets += provisioningService.reconcile(
            ProvisionUser(id, tenantId, user.email ?: "", user.displayName ?: "", active = !suspend),
        )

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.ADMIN,
                actorId = admin.userId.toString(),
                action = if (suspend) "identity.suspended_by_admin" else "identity.reactivated_by_admin",
                result = AuditResult.SUCCESS,
                reason = "targetUser=$id; sessionsEnded=$sessionsEnded; downstreamFailures=${targets.count { !it.ok }}",
                sourceIp = httpRequest.remoteAddr,
            ),
        )

        return LifecycleResponse(id, if (suspend) "SUSPENDED" else "ACTIVE", sessionsEnded, targets)
    }

    private fun googleTarget(tenantId: UUID, user: RemoteUser, suspend: Boolean): List<TargetResult> {
        val config = googleWorkspaceConfigService.loadProvisioningConfig(tenantId) ?: return emptyList()
        val email = user.email ?: return emptyList()
        if (!config.manages(email)) {
            return listOf(TargetResult("Google Workspace", "skipped", ok = true, error = "Email is not on the Google domain ${config.domain}"))
        }
        val result = try {
            val applied = googleWorkspaceDirectoryClient.setSuspended(config.adminEmail, config.serviceAccountKey, email, suspend)
            if (applied) {
                TargetResult("Google Workspace", if (suspend) "suspended" else "reactivated", ok = true)
            } else {
                TargetResult("Google Workspace", "skipped", ok = true, error = "No matching Google account")
            }
        } catch (ex: GoogleProvisioningException) {
            TargetResult("Google Workspace", "failed", ok = false, error = ex.message)
        }
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-tenant-svc",
                action = if (suspend) "google_workspace_user.suspended" else "google_workspace_user.reactivated",
                result = if (result.ok) AuditResult.SUCCESS else AuditResult.FAILURE,
                reason = result.error,
            ),
        )
        return listOf(result)
    }

    // The target id comes from the URL, so confirm it is really a user of this tenant first.
    private fun requireUserInTenant(userId: UUID, tenantId: UUID): RemoteUser {
        val user = identityClient.findUser(userId)
        if (user == null || user.tenantId != tenantId) throw UserNotFoundForDeletionException(userId)
        return user
    }
}
