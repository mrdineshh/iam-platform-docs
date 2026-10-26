package com.iamplatform.tenant

import org.springframework.stereotype.Component
import java.util.UUID

// Added for Service 14 (iam-admin-console). 401 vs 403 distinction matters
// to the console's own UI copy ("your session expired" vs "you don't have
// permission") -- see docs/specs/iam-admin-console-SPEC.md Section 4.
class AdminSessionInvalidException : RuntimeException("Session unknown or expired")
class AdminAccessDeniedException(message: String) : RuntimeException(message)

/**
 * Gates every admin-console-only endpoint added in this service. Not shared
 * via iam-service-kit -- this is authorization business logic, not
 * technical infra, and BUILD_PLAN.md Section 4.5 explicitly restricts
 * iam-service-kit to technical infra only. Same duplicate-per-service
 * pattern iam-policy-svc's own copy of this class follows.
 */
@Component
class AdminAccessGuard(
    private val sessionClient: SessionClient,
    private val identityClient: IdentityClient,
) {
    fun requireTenantAdmin(sessionToken: String, tenantId: UUID) {
        val session = requireValidSession(sessionToken)
        if (session.tenantId != tenantId) {
            throw AdminAccessDeniedException("session does not belong to this tenant")
        }
        val user = identityClient.findUser(session.userId)
            ?: throw AdminAccessDeniedException("user for this session no longer exists")
        if (user.role != RemoteUserRole.ADMIN) {
            throw AdminAccessDeniedException("admin role required")
        }
    }

    /**
     * Confirms the caller has a live session, without requiring ADMIN --
     * used by the self-service 2FA endpoints (any authenticated user
     * enrolling their own device, not an org-wide admin action).
     */
    fun requireValidSession(sessionToken: String): RemoteSession =
        sessionClient.find(sessionToken) ?: throw AdminSessionInvalidException()
}
