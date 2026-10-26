package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

@Service
class SamlSpService(
    private val repository: SamlSpRepository,
    private val tenantRepository: TenantRepository,
    private val groupRepository: SamlSpGroupRepository,
    private val auditPublisher: AuditPublisher,
) {

    fun createSamlSp(request: CreateSamlSpRequest): SamlSpEntity {
        if (!tenantRepository.existsById(request.tenantId)) {
            throw TenantNotFoundException(request.tenantId)
        }
        if (repository.existsBySpEntityId(request.spEntityId)) {
            throw SamlSpEntityIdAlreadyExistsException(request.spEntityId)
        }

        val sp = repository.save(
            SamlSpEntity(
                id = UUID.randomUUID(),
                tenantId = request.tenantId,
                name = request.name,
                spEntityId = request.spEntityId,
                acsUrl = request.acsUrl,
                launchUrl = request.launchUrl,
            ),
        )

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = sp.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-tenant-svc",
                action = "saml_sp.created",
                result = AuditResult.SUCCESS,
                reason = "spEntityId=${sp.spEntityId}",
            ),
        )

        return sp
    }

    fun getSamlSp(id: UUID): SamlSpEntity =
        repository.findById(id).orElseThrow { SamlSpNotFoundException(id) }

    fun listSamlSps(tenantId: UUID): List<SamlSpEntity> =
        repository.findByTenantId(tenantId)

    // Group-based launchpad visibility counterpart to
    // OidcClientService.listClientsForGroup -- see that method's comment.
    fun listSamlSpsForGroup(groupId: UUID): List<SamlSpEntity> {
        val spIds = groupRepository.findByGroupId(groupId).map { it.samlSpId }
        return if (spIds.isEmpty()) emptyList() else repository.findAllById(spIds)
    }

    fun getGroupIds(spId: UUID): List<UUID> {
        if (!repository.existsById(spId)) throw SamlSpNotFoundException(spId)
        return groupRepository.findBySamlSpId(spId).map { it.groupId }
    }

    @Transactional
    fun setGroups(spId: UUID, groupIds: List<UUID>) {
        if (!repository.existsById(spId)) throw SamlSpNotFoundException(spId)
        groupRepository.deleteBySamlSpId(spId)
        groupRepository.saveAll(groupIds.distinct().map { SamlSpGroupEntity(UUID.randomUUID(), spId, it) })
    }

    // Internal-only (iam-oidcprovider-svc resolving an incoming
    // AuthnRequest's Issuer) -- no session gating, same unauthenticated
    // mTLS-only-inbound pattern as OidcClientController.getClient.
    fun findBySpEntityId(spEntityId: String): SamlSpEntity? =
        repository.findBySpEntityId(spEntityId)
}
