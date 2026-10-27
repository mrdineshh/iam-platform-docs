package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

/**
 * Admin-console "create user" self-service page. Admin-gated (same
 * AdminAccessGuard every other Service-14 endpoint uses) -- proxies to
 * iam-identity-svc, which is mTLS-only inbound and so can't be called
 * directly from the browser SPA.
 *
 * Also enrolls the new user's first 2FA device in the same call. This
 * isn't optional: iam-auth-svc requires a second factor on every login,
 * unconditionally, with no first-login grace period (see AuthService.kt's
 * own comment -- deliberate MVP scope, not a bug). A brand-new user with
 * zero devices literally cannot log in, and self-service enrollment
 * (SelfServiceController) requires a session they can't get without
 * logging in first -- a real chicken-and-egg gap. Bootstrapping the first
 * device here, admin-mediated, mirrors how enterprise IT onboarding
 * actually works (the admin hands the QR to the new hire directly); the
 * self-service page still covers everything after that first device.
 */
@RestController
@RequestMapping("/api/v1/admin/users")
class AdminUserController(
    private val identityClient: IdentityClient,
    private val deviceClient: DeviceClient,
    private val adminAccessGuard: AdminAccessGuard,
    private val googleWorkspaceConfigService: GoogleWorkspaceConfigService,
    private val googleWorkspaceDirectoryClient: GoogleWorkspaceDirectoryClient,
    private val provisioningService: ProvisioningService,
    private val auditPublisher: AuditPublisher,
) {
    @PostMapping
    fun createUser(
        @Valid @RequestBody request: CreateUserRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<CreatedUserResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, request.tenantId)
        val created = identityClient.createUser(
            CreateRemoteUserRequest(
                tenantId = request.tenantId,
                email = request.email,
                displayName = request.displayName,
                password = request.password,
                role = request.role,
            ),
        )
        val device = deviceClient.enroll(created.tenantId, created.id)

        // Best-effort, never blocking: this platform's own account is the
        // real identity (AP-3, we never let an upstream/downstream system's
        // state gate our own session issuance), so a Google-side failure
        // here must not undo or fail the user creation that already
        // succeeded. See GoogleWorkspaceDirectoryClient's doc comment for
        // why the generated Google password is never surfaced anywhere --
        // only our platform's password ever matters for sign-in once SSO
        // redirect mode is set on the account's OU.
        var googleProvisioned = false
        var googleError: String? = null
        val googleConfig = if (request.createInGoogleWorkspace) {
            googleWorkspaceConfigService.loadProvisioningConfig(request.tenantId)
        } else {
            null
        }
        if (googleConfig != null) {
            try {
                val (givenName, familyName) = splitDisplayName(request.displayName)
                googleWorkspaceDirectoryClient.provisionUser(
                    googleConfig.copy(primaryEmail = request.email, givenName = givenName, familyName = familyName),
                )
                googleProvisioned = true
            } catch (ex: GoogleProvisioningException) {
                googleError = ex.message
            }
            auditPublisher.publish(
                AuditEvent(
                    correlationId = CorrelationId.get(),
                    tenantId = request.tenantId,
                    actorType = ActorType.SYSTEM,
                    actorId = "iam-tenant-svc",
                    action = "google_workspace_user.provisioned",
                    result = if (googleProvisioned) AuditResult.SUCCESS else AuditResult.FAILURE,
                    reason = googleError,
                ),
            )
        }

        // Push the new user to every SCIM-connected app (best effort, like Google above).
        val appProvisioning = provisioningService.reconcile(
            ProvisionUser(created.id, request.tenantId, created.email, created.displayName, active = true),
        )

        return ResponseEntity.status(HttpStatus.CREATED).body(
            CreatedUserResponse(
                id = created.id,
                tenantId = created.tenantId,
                email = created.email,
                displayName = created.displayName,
                role = created.role,
                totpSecret = device.totpSecret,
                provisioningUri = device.provisioningUri,
                googleWorkspaceProvisioned = googleProvisioned,
                googleWorkspaceError = googleError,
                appProvisioning = appProvisioning,
            ),
        )
    }

    // "Deleted from everywhere" (2026-10-26, docs/DECISIONS.md, the
    // explicit ask that surfaced this gap): deletes the platform account
    // outright, then best-effort deletes the matching Google Workspace
    // account too, if one exists. Connected-app access for any session
    // this user already held is cut off by iam-enforcement-svc's own
    // identity-existence check (added the same day) on that session's
    // very next request -- nothing extra needed here for that part.
    @DeleteMapping("/{id}")
    fun deleteUser(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<DeletedUserResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        val user = identityClient.findUser(id)
        if (user == null || user.tenantId != tenantId) {
            throw UserNotFoundForDeletionException(id)
        }

        identityClient.deleteUser(id)

        // Delete the accounts we created in SCIM-connected apps (only those; see ProvisioningService).
        val appProvisioning = provisioningService.deprovision(tenantId, id, user.email)

        var googleDeleted = false
        var googleError: String? = null
        val googleConfig = googleWorkspaceConfigService.loadProvisioningConfig(tenantId)
        if (googleConfig != null && user.email != null && googleConfig.manages(user.email)) {
            try {
                googleWorkspaceDirectoryClient.deleteUser(googleConfig.adminEmail, googleConfig.serviceAccountKey, user.email)
                googleDeleted = true
            } catch (ex: GoogleProvisioningException) {
                googleError = ex.message
            }
            auditPublisher.publish(
                AuditEvent(
                    correlationId = CorrelationId.get(),
                    tenantId = tenantId,
                    actorType = ActorType.SYSTEM,
                    actorId = "iam-tenant-svc",
                    action = "google_workspace_user.deleted",
                    result = if (googleDeleted) AuditResult.SUCCESS else AuditResult.FAILURE,
                    reason = googleError,
                ),
            )
        }

        return ResponseEntity.ok(
            DeletedUserResponse(
                id = id,
                googleWorkspaceDeleted = googleDeleted,
                googleWorkspaceError = googleError,
                appProvisioning = appProvisioning,
            ),
        )
    }

    // FR-3.5: an admin clears a lockout (temporary or permanent) so the user can
    // sign in again without waiting. Recorded with the admin as actor.
    @PostMapping("/{id}/unlock")
    fun unlockUser(
        @PathVariable id: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<Void> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        val user = identityClient.findUser(id)
        if (user == null || user.tenantId != tenantId) {
            throw UserNotFoundForDeletionException(id)
        }
        val admin = adminAccessGuard.requireValidSession(sessionToken)

        identityClient.unlockUser(id)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.ADMIN,
                actorId = admin.userId.toString(),
                action = "identity.unlocked_by_admin",
                result = AuditResult.SUCCESS,
                reason = "targetUser=$id",
                sourceIp = httpRequest.remoteAddr,
            ),
        )
        return ResponseEntity.noContent().build()
    }

}
