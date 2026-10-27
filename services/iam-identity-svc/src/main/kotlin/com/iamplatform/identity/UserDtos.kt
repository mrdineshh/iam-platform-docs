package com.iamplatform.identity

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Size
import java.time.Instant
import java.util.UUID

data class CreateUserRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    @field:Email
    val email: String,

    @field:NotBlank
    @field:Size(max = 255)
    val displayName: String,

    // Optional -- JIT-provisioned users (Service 8, Google Workspace) have no
    // local password at all. Only set when a caller explicitly provides one.
    @field:Size(min = 8)
    val password: String? = null,

    // Added for Service 14 (iam-admin-console). Defaults to USER.
    val role: UserRole? = null,
)

data class UpdateStatusRequest(
    @field:NotNull
    val status: UserStatus,
)

// Added for Service 14 (iam-admin-console) -- bootstraps the first admin
// user (see docs/specs/iam-admin-console-SPEC.md Section 6: deliberately
// unauthenticated in this pass, chicken-and-egg problem, flagged not hidden).
data class UpdateRoleRequest(
    @field:NotNull
    val role: UserRole,
)

data class AssignGroupRequest(
    val groupId: UUID? = null,
)

data class SetPasswordRequest(
    @field:NotBlank
    @field:Size(min = 8)
    val password: String,
)

data class VerifyPasswordRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    val email: String,

    @field:NotBlank
    val password: String,
)

data class VerifyPasswordResponse(
    val valid: Boolean,
    val userId: UUID? = null,
    val status: UserStatus? = null,
    val role: UserRole? = null,
    // Added for group-based policy -- iam-auth-svc forwards this as the
    // evaluate call's ouId, so group-scoped 2FA/IP policy actually applies.
    val groupId: UUID? = null,

    // Set only when the CORRECT password was supplied for a locked account
    // (valid stays false): a wrong password gets the same generic answer as an
    // unknown user, so lock state never leaks to someone guessing passwords.
    val locked: Boolean = false,
    val lockedUntil: Instant? = null,
    val permanentlyLocked: Boolean = false,
)

data class UserResponse(
    val id: UUID,
    val tenantId: UUID,
    val email: String,
    val displayName: String,
    val status: UserStatus,
    val role: UserRole,
    val groupId: UUID?,
    val createdAt: Instant,
    val locked: Boolean = false,
    val lockedUntil: Instant? = null,
    val permanentlyLocked: Boolean = false,
)

fun UserEntity.toResponse(): UserResponse =
    UserResponse(
        id = id,
        tenantId = tenantId,
        email = email,
        displayName = displayName,
        status = status,
        role = role,
        groupId = groupId,
        createdAt = createdAt,
        locked = isLockedAt(Instant.now()),
        lockedUntil = lockedUntil?.takeIf { it.isAfter(Instant.now()) },
        permanentlyLocked = permanentlyLocked,
    )

data class CreateGroupRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    @field:Size(max = 255)
    val name: String,
)

data class GroupResponse(
    val id: UUID,
    val tenantId: UUID,
    val name: String,
    val createdAt: Instant,
)

fun GroupEntity.toResponse(): GroupResponse = GroupResponse(id, tenantId, name, createdAt)
