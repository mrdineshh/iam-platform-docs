package com.iamplatform.identity

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import java.time.Clock
import java.time.Duration
import java.util.UUID

@Service
class UserService(
    private val repository: UserRepository,
    private val tenantClient: TenantClient,
    private val auditPublisher: AuditPublisher,
    private val passwordService: PasswordService,
    private val policyClient: PolicyClient,
    private val clock: Clock = Clock.systemUTC(),
) {

    fun createUser(request: CreateUserRequest): UserEntity {
        if (!tenantClient.exists(request.tenantId)) {
            throw TenantNotFoundException(request.tenantId)
        }
        if (repository.existsByTenantIdAndEmail(request.tenantId, request.email)) {
            throw EmailAlreadyExistsException(request.email)
        }
        request.password?.let { enforcePasswordRules(request.tenantId, it) }

        val user = repository.save(
            UserEntity(
                id = UUID.randomUUID(),
                tenantId = request.tenantId,
                email = request.email,
                displayName = request.displayName,
                passwordHash = request.password?.let { passwordService.hash(it) },
                role = request.role ?: UserRole.USER,
            ),
        )

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = user.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-identity-svc",
                action = "identity.created",
                result = AuditResult.SUCCESS,
            ),
        )

        return user
    }

    fun getUser(id: UUID): UserEntity =
        repository.findById(id).orElseThrow { UserNotFoundException(id) }

    // Added for the admin-console "Switch to user" picker. No audit event --
    // listing is not itself a security-relevant action; the actual
    // impersonation (iam-tenant-svc's /api/v1/admin/impersonate) is what
    // gets audited.
    fun listUsers(tenantId: UUID): List<UserEntity> = repository.findByTenantId(tenantId)

    fun updateStatus(id: UUID, request: UpdateStatusRequest): UserEntity {
        val user = getUser(id)
        val previousStatus = user.status
        user.status = request.status
        repository.save(user)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = user.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-identity-svc",
                action = "identity.status_changed",
                result = AuditResult.SUCCESS,
                reason = "$previousStatus -> ${request.status}",
            ),
        )

        return user
    }

    fun updateRole(id: UUID, request: UpdateRoleRequest): UserEntity {
        val user = getUser(id)
        val previousRole = user.role
        user.role = request.role
        repository.save(user)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = user.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-identity-svc",
                action = "identity.role_changed",
                result = AuditResult.SUCCESS,
                reason = "$previousRole -> ${request.role}",
            ),
        )

        return user
    }

    fun assignGroup(id: UUID, request: AssignGroupRequest): UserEntity {
        val user = getUser(id)
        val previousGroup = user.groupId
        user.groupId = request.groupId
        repository.save(user)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = user.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-identity-svc",
                action = "identity.group_changed",
                result = AuditResult.SUCCESS,
                reason = "$previousGroup -> ${request.groupId}",
            ),
        )

        return user
    }

    // Hard delete, not a status flag -- "deleted from everywhere" means
    // gone, not just disabled (SUSPENDED already covers "disabled but
    // recoverable"). Existing audit_events referencing this user's id as
    // actorId are untouched -- that history stays readable by id even
    // after the row backing it is gone, same as any other foreign
    // reference in this system (cross-service, logical only, no DB-level
    // FK). Returns the entity as it was immediately before deletion so
    // the caller (iam-tenant-svc, which also needs the email to delete
    // the matching Google Workspace account) doesn't need a second call.
    fun deleteUser(id: UUID): UserEntity {
        val user = getUser(id)
        repository.delete(user)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = user.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-identity-svc",
                action = "identity.deleted",
                result = AuditResult.SUCCESS,
                reason = "email=${user.email}",
            ),
        )

        return user
    }

    fun setPassword(id: UUID, request: SetPasswordRequest) {
        val user = getUser(id)
        enforcePasswordRules(user.tenantId, request.password)
        user.passwordHash = passwordService.hash(request.password)
        repository.save(user)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = user.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-identity-svc",
                action = "identity.password_set",
                result = AuditResult.SUCCESS,
            ),
        )
    }

    // No audit event published here -- this is an internal credential check,
    // not itself the security decision. iam-auth-svc (Service 7), the actual
    // login orchestrator, publishes the login outcome. Same reasoning as
    // iam-policy-svc's evaluate endpoint (docs/DECISIONS.md, Service 5 entry).
    fun verifyPassword(request: VerifyPasswordRequest): VerifyPasswordResponse {
        val user = repository.findByTenantIdAndEmail(request.tenantId, request.email)
            ?: return VerifyPasswordResponse(valid = false)
        val hash = user.passwordHash ?: return VerifyPasswordResponse(valid = false)
        val now = clock.instant()
        val lockedNow = user.isLockedAt(now)

        if (!passwordService.matches(request.password, hash)) {
            // Deliberately the same shape as "user not found" above -- never
            // give a caller a way to distinguish a bad email from a bad
            // password (user enumeration). A locked account also answers this
            // way to a wrong guess: lock state is revealed only to someone who
            // already knows the password (below). Guesses against a locked
            // account are not counted, so a lock can't be extended by an attacker.
            if (!lockedNow) recordFailedAttempt(user, now)
            return VerifyPasswordResponse(valid = false)
        }

        if (lockedNow) {
            return VerifyPasswordResponse(
                valid = false,
                locked = true,
                lockedUntil = user.lockedUntil?.takeIf { it.isAfter(now) },
                permanentlyLocked = user.permanentlyLocked,
            )
        }

        // A correct password clears the counter and any lock that has expired.
        if (user.failedLoginAttempts != 0 || user.lockedUntil != null) {
            user.failedLoginAttempts = 0
            user.lockedUntil = null
            repository.save(user)
        }
        return VerifyPasswordResponse(valid = true, userId = user.id, status = user.status, role = user.role, groupId = user.groupId)
    }

    // FR-3.5. The counter is incremented atomically in the database; the lock
    // decision then reads the tenant's threshold. If iam-policy-svc cannot be
    // reached the failure is still counted and the lock simply engages on the
    // next failed attempt once settings are readable: an outage must neither
    // lock everyone out nor lose the count.
    private fun recordFailedAttempt(user: UserEntity, now: java.time.Instant) {
        repository.incrementFailedAttempts(user.id)
        val settings = try {
            policyClient.securitySettings(user.tenantId)
        } catch (ex: Exception) {
            return
        }
        if (settings.lockoutThreshold <= 0) return

        val fresh = repository.findById(user.id).orElse(null) ?: return
        if (fresh.isLockedAt(now) || fresh.failedLoginAttempts < settings.lockoutThreshold) return

        val permanent = settings.lockoutPermanent
        fresh.failedLoginAttempts = 0
        if (permanent) {
            fresh.permanentlyLocked = true
        } else {
            fresh.lockedUntil = now.plus(Duration.ofMinutes(settings.lockoutDurationMinutes.toLong()))
        }
        repository.save(fresh)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = fresh.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-identity-svc",
                action = "identity.account_locked",
                result = AuditResult.SUCCESS,
                reason = "after ${settings.lockoutThreshold} failed sign-ins; " +
                    (if (permanent) "until an admin unlocks it" else "for ${settings.lockoutDurationMinutes} minutes") +
                    "; user=${fresh.id}",
            ),
        )
    }

    /** Clears the lock and the failed-attempt counter. The admin who asked is audited by iam-tenant-svc. */
    fun unlockUser(id: UUID): UserEntity {
        val user = getUser(id)
        user.failedLoginAttempts = 0
        user.lockedUntil = null
        user.permanentlyLocked = false
        repository.save(user)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = user.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-identity-svc",
                action = "identity.account_unlocked",
                result = AuditResult.SUCCESS,
                reason = "user=${user.id}",
            ),
        )
        return user
    }

    // Fails closed: if the tenant's rules can't be read, the password is not
    // accepted (the caller gets the standard 503), rather than silently
    // falling back to weaker rules than the tenant configured.
    private fun enforcePasswordRules(tenantId: UUID, password: String) {
        PasswordRules.enforce(password, policyClient.securitySettings(tenantId))
    }
}
