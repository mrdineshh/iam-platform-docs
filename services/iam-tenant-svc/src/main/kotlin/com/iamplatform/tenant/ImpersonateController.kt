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
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.bind.annotation.RestControllerAdvice
import java.util.UUID

/**
 * Admin-console "Switch to user" feature -- an admin acts as another user in
 * their own tenant without that user's password or MFA. This is a real,
 * security-sensitive capability (not a UI convenience), so it's gated and
 * audited more heavily than the other admin-console proxy endpoints in this
 * file's siblings:
 *   - requireTenantAdmin (same guard every other admin-gated endpoint here
 *     uses) confirms the caller is genuinely an ADMIN of this exact tenant.
 *   - Every impersonation publishes an immutable audit event naming BOTH the
 *     admin and the target user -- there is no way to switch to a user
 *     without it being recorded, matching this platform's existing
 *     break-glass-access auditing principle (CLAUDE.md AP-8) even though
 *     this isn't literally break-glass.
 *   - The target user is re-resolved from iam-identity-svc and checked
 *     against this exact tenantId server-side -- never trusts that a user
 *     shown in the picker UI is still a safe target (defense in depth
 *     against a stale client-side list).
 */
@RestController
class ImpersonateController(
    private val identityClient: IdentityClient,
    private val sessionClient: SessionClient,
    private val adminAccessGuard: AdminAccessGuard,
    private val auditPublisher: AuditPublisher,
) {
    // Added alongside impersonation -- the picker needs a list of this
    // tenant's users to choose from. Admin-gated, same as every other
    // admin-console listing endpoint (no secrets in the response).
    @GetMapping("/api/v1/admin/users")
    fun listUsers(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<AdminUserListEntry>> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        val users = identityClient.listUsers(tenantId)
            .map {
                AdminUserListEntry(
                    it.id, it.email, it.displayName, it.status, it.role, it.groupId,
                    it.locked, it.lockedUntil, it.permanentlyLocked,
                )
            }
        return ResponseEntity.ok(users)
    }

    @PostMapping("/api/v1/admin/impersonate")
    fun impersonate(
        @Valid @RequestBody request: ImpersonateRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<ImpersonateResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, request.tenantId)
        val adminSession = adminAccessGuard.requireValidSession(sessionToken)

        // Re-resolved from iam-identity-svc's own tenant-scoped list, not
        // trusted from the request body alone -- a target id that isn't
        // actually in this tenant (stale client-side picker, tampered
        // request) is rejected here, not just filtered client-side.
        val target = identityClient.listUsers(request.tenantId).find { it.id == request.targetUserId }
            ?: throw CannotImpersonateException("No such user in this tenant")

        val issued = sessionClient.issue(request.tenantId, request.targetUserId, httpRequest.remoteAddr)

        // Audited unconditionally, success path only reached this far --
        // every switch, by definition, is "success" (a denial throws above
        // before this runs, which GlobalExceptionHandler maps to 403/404
        // without an audit event, same as this file's sibling endpoints).
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = request.tenantId,
                actorType = ActorType.ADMIN,
                actorId = adminSession.userId.toString(),
                action = "identity.impersonated",
                result = AuditResult.SUCCESS,
                reason = "admin ${adminSession.userId} switched to user ${request.targetUserId}",
                sourceIp = httpRequest.remoteAddr,
            ),
        )

        return ResponseEntity.ok(
            ImpersonateResponse(
                token = issued.token,
                sessionId = issued.sessionId,
                userId = target.id,
                email = target.email,
                displayName = target.displayName,
                role = target.role,
                expiresAt = issued.expiresAt,
            ),
        )
    }
}

@RestControllerAdvice
class ImpersonateExceptionHandler {
    @ExceptionHandler(CannotImpersonateException::class)
    fun handle(ex: CannotImpersonateException, request: HttpServletRequest): ResponseEntity<com.iamplatform.servicekit.error.ErrorResponse> =
        ResponseEntity.status(HttpStatus.NOT_FOUND).body(
            com.iamplatform.servicekit.error.ErrorResponse.of(HttpStatus.NOT_FOUND.value(), "Not Found", ex.message ?: "", request.requestURI),
        )
}
