package com.iamplatform.identity

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

enum class UserStatus { ACTIVE, SUSPENDED }

// Added for Service 14 (iam-admin-console) -- see docs/DECISIONS.md.
// BUILD_PLAN.md's "two fixed roles" deviation (D3), actually implemented
// for the first time here.
enum class UserRole { ADMIN, USER }

@Entity
@Table(name = "users")
class UserEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "tenant_id", nullable = false)
    var tenantId: UUID,

    @Column(name = "email", nullable = false)
    var email: String,

    @Column(name = "display_name", nullable = false)
    var displayName: String,

    @Column(name = "password_hash")
    var passwordHash: String? = null,

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    var status: UserStatus = UserStatus.ACTIVE,

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false, length = 16)
    var role: UserRole = UserRole.USER,

    // Added for group-based policy (2FA requirement, IP allowlisting) --
    // null means "no group", which the policy engine treats as "no OU-level
    // policy applies, fall through to tenant-level" (same as every other
    // OU-scoped attribute already does).
    @Column(name = "group_id")
    var groupId: UUID? = null,

    // Account lockout (FR-3.5). Reset on a successful sign-in or an admin unlock.
    @Column(name = "failed_login_attempts", nullable = false)
    var failedLoginAttempts: Int = 0,

    @Column(name = "locked_until")
    var lockedUntil: Instant? = null,

    @Column(name = "permanently_locked", nullable = false)
    var permanentlyLocked: Boolean = false,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),
) {
    fun isLockedAt(now: Instant): Boolean = permanentlyLocked || (lockedUntil?.isAfter(now) == true)
}

@Entity
@Table(name = "groups")
class GroupEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "tenant_id", nullable = false)
    var tenantId: UUID,

    @Column(name = "name", nullable = false)
    var name: String,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),
)
