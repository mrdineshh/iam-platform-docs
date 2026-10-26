package com.iamplatform.policy

import org.springframework.stereotype.Component
import java.util.UUID

// Added for Service 14 (iam-admin-console). Same shape as
// iam-tenant-svc's own copy (see docs/specs/iam-admin-console-SPEC.md
// Section 0 for why this isn't shared via iam-service-kit).
class AdminSessionInvalidException : RuntimeException("Session unknown or expired")
class AdminAccessDeniedException(message: String) : RuntimeException(message)

@Component
class AdminAccessGuard(
    private val sessionClient: SessionClient,
    private val identityClient: IdentityClient,
) {
    fun requireTenantAdmin(sessionToken: String, tenantId: UUID) {
        val session = sessionClient.find(sessionToken) ?: throw AdminSessionInvalidException()
        if (session.tenantId != tenantId) {
            throw AdminAccessDeniedException("session does not belong to this tenant")
        }
        val user = identityClient.findUser(session.userId)
            ?: throw AdminAccessDeniedException("user for this session no longer exists")
        if (user.role != RemoteUserRole.ADMIN) {
            throw AdminAccessDeniedException("admin role required")
        }
    }
}
