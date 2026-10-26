package com.iamplatform.identity

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class UserService(
    private val repository: UserRepository,
    private val tenantClient: TenantClient,
    private val auditPublisher: AuditPublisher,
    private val passwordService: PasswordService,
) {

    fun createUser(request: CreateUserRequest): UserEntity {
        if (!tenantClient.exists(request.tenantId)) {
            throw TenantNotFoundException(request.tenantId)
        }
        if (repository.existsByTenantIdAndEmail(request.tenantId, request.email)) {
            throw EmailAlreadyExistsException(request.email)
        }

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

        return if (passwordService.matches(request.password, hash)) {
            VerifyPasswordResponse(valid = true, userId = user.id, status = user.status, role = user.role, groupId = user.groupId)
        } else {
            // Deliberately the same shape as "user not found" above -- never
            // give a caller a way to distinguish a bad email from a bad
            // password (user enumeration).
            VerifyPasswordResponse(valid = false)
        }
    }
}
