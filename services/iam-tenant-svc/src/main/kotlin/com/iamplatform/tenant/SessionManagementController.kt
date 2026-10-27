package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant
import java.util.UUID

data class SessionSummary(
    val sessionId: UUID,
    val sourceIp: String?,
    val deviceId: String?,
    val issuedAt: Instant,
    val expiresAt: Instant,
    // True for the session making this very request -- lets the UI label it
    // "This session" and keeps users from signing themselves out by accident.
    val current: Boolean,
)

data class RevokedSessionsResponse(val revoked: Int)

/**
 * Active-session management: an admin can list and end any user's sessions in
 * their tenant ("sign out everywhere" after a lost laptop or a departing
 * employee), and any user can list and end their own. Ending a session
 * deletes it in iam-session-svc, so iam-enforcement-svc rejects the very next
 * request made with that token (AP-2: sessions are killable mid-flight).
 * Admin revokes are audited with the admin as actor (FR-11.1).
 */
@RestController
@RequestMapping("/api/v1")
class SessionManagementController(
    private val sessionClient: SessionClient,
    private val identityClient: IdentityClient,
    private val adminAccessGuard: AdminAccessGuard,
    private val auditPublisher: AuditPublisher,
) {

    @GetMapping("/admin/users/{userId}/sessions")
    fun listUserSessions(
        @PathVariable userId: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<List<SessionSummary>> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        requireUserInTenant(userId, tenantId)
        val callerSessionId = adminAccessGuard.requireValidSession(sessionToken).sessionId
        return ResponseEntity.ok(sessionClient.listForUser(tenantId, userId).map { it.toSummary(callerSessionId) })
    }

    @DeleteMapping("/admin/users/{userId}/sessions")
    fun revokeAllUserSessions(
        @PathVariable userId: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<RevokedSessionsResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        requireUserInTenant(userId, tenantId)
        val admin = adminAccessGuard.requireValidSession(sessionToken)

        val count = sessionClient.listForUser(tenantId, userId).size
        sessionClient.terminateAllForUser(tenantId, userId, "admin-revoked-by-${admin.userId}")
        audit(tenantId, admin.userId, "session.revoked_by_admin", "targetUser=$userId; allSessions=$count", httpRequest)
        return ResponseEntity.ok(RevokedSessionsResponse(count))
    }

    @DeleteMapping("/admin/users/{userId}/sessions/{sessionId}")
    fun revokeUserSession(
        @PathVariable userId: UUID,
        @PathVariable sessionId: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<Void> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        requireUserInTenant(userId, tenantId)
        val admin = adminAccessGuard.requireValidSession(sessionToken)

        sessionClient.terminateOneForUser(tenantId, userId, sessionId, "admin-revoked-by-${admin.userId}")
        audit(tenantId, admin.userId, "session.revoked_by_admin", "targetUser=$userId; sessionId=$sessionId", httpRequest)
        return ResponseEntity.noContent().build()
    }

    @GetMapping("/me/sessions")
    fun listMySessions(@RequestHeader("X-Session-Token") sessionToken: String): ResponseEntity<List<SessionSummary>> {
        val me = adminAccessGuard.requireValidSession(sessionToken)
        return ResponseEntity.ok(sessionClient.listForUser(me.tenantId, me.userId).map { it.toSummary(me.sessionId) })
    }

    @DeleteMapping("/me/sessions/{sessionId}")
    fun revokeMySession(
        @PathVariable sessionId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<Void> {
        val me = adminAccessGuard.requireValidSession(sessionToken)
        sessionClient.terminateOneForUser(me.tenantId, me.userId, sessionId, "user-revoked")
        return ResponseEntity.noContent().build()
    }

    // "Sign out of all other devices" -- everything except the session making
    // this request.
    @DeleteMapping("/me/sessions")
    fun revokeMyOtherSessions(@RequestHeader("X-Session-Token") sessionToken: String): ResponseEntity<RevokedSessionsResponse> {
        val me = adminAccessGuard.requireValidSession(sessionToken)
        var revoked = 0
        for (session in sessionClient.listForUser(me.tenantId, me.userId)) {
            if (session.sessionId == me.sessionId) continue
            try {
                sessionClient.terminateOneForUser(me.tenantId, me.userId, session.sessionId, "user-revoked-others")
                revoked++
            } catch (_: SessionNotFoundForRevokeException) {
                // Expired or ended between the list and the delete -- already gone, which is the goal.
            }
        }
        return ResponseEntity.ok(RevokedSessionsResponse(revoked))
    }

    // The target id comes from the URL, so confirm it really is a user of this
    // tenant before touching its sessions -- an admin of tenant A must never be
    // able to act on tenant B's users by guessing an id.
    private fun requireUserInTenant(userId: UUID, tenantId: UUID) {
        val user = identityClient.findUser(userId)
        if (user == null || user.tenantId != tenantId) throw UserNotFoundForDeletionException(userId)
    }

    private fun RemoteSessionRecord.toSummary(callerSessionId: UUID) =
        SessionSummary(sessionId, sourceIp, deviceId, issuedAt, expiresAt, current = sessionId == callerSessionId)

    private fun audit(tenantId: UUID, adminId: UUID, action: String, reason: String, httpRequest: HttpServletRequest) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.ADMIN,
                actorId = adminId.toString(),
                action = action,
                result = AuditResult.SUCCESS,
                reason = reason,
                sourceIp = httpRequest.remoteAddr,
            ),
        )
    }
}
