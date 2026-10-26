package com.iamplatform.identity

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import java.util.UUID

class GroupNotFoundException(id: UUID) : RuntimeException("No group with id $id")

@Service
class GroupService(
    private val repository: GroupRepository,
    private val userRepository: UserRepository,
    private val auditPublisher: AuditPublisher,
) {
    fun createGroup(request: CreateGroupRequest): GroupEntity {
        val group = repository.save(
            GroupEntity(id = UUID.randomUUID(), tenantId = request.tenantId, name = request.name),
        )

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = group.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-identity-svc",
                action = "group.created",
                result = AuditResult.SUCCESS,
                reason = group.name,
            ),
        )

        return group
    }

    fun listGroups(tenantId: UUID): List<GroupEntity> = repository.findByTenantId(tenantId)

    fun getGroup(id: UUID): GroupEntity = repository.findById(id).orElseThrow { GroupNotFoundException(id) }

    // Unassigns every member first (so nobody is left pointing at a
    // deleted group) before removing the group itself. iam-tenant-svc's
    // proxy additionally cleans up this group's oidc_client_groups /
    // saml_sp_groups rows, which live in its own tenant_db.
    fun deleteGroup(id: UUID) {
        val group = getGroup(id)
        userRepository.findByGroupId(id).forEach {
            it.groupId = null
            userRepository.save(it)
        }
        repository.delete(group)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = group.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-identity-svc",
                action = "group.deleted",
                result = AuditResult.SUCCESS,
                reason = group.name,
            ),
        )
    }
}
