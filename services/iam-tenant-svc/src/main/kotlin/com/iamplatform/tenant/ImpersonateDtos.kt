package com.iamplatform.tenant

import jakarta.validation.constraints.NotNull
import java.util.UUID

data class ImpersonateRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotNull
    val targetUserId: UUID,
)

data class ImpersonateResponse(
    val token: String,
    val sessionId: UUID,
    val userId: UUID,
    val email: String,
    val displayName: String,
    val role: RemoteUserRole,
    val expiresAt: java.time.Instant,
)

data class AdminUserListEntry(
    val id: UUID,
    val email: String,
    val displayName: String,
    val status: RemoteUserStatus,
    val role: RemoteUserRole,
    val groupId: UUID? = null,
    val locked: Boolean = false,
    val lockedUntil: java.time.Instant? = null,
    val permanentlyLocked: Boolean = false,
)

class CannotImpersonateException(message: String) : RuntimeException(message)
