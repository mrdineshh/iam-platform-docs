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
class OidcClientService(
    private val repository: OidcClientRepository,
    private val tenantRepository: TenantRepository,
    private val groupRepository: OidcClientGroupRepository,
    private val secretHasher: ClientSecretHasher,
    private val auditPublisher: AuditPublisher,
) {

    fun createClient(request: CreateOidcClientRequest): Pair<OidcClientEntity, String> {
        if (!tenantRepository.existsById(request.tenantId)) {
            throw TenantNotFoundException(request.tenantId)
        }

        val secret = ClientSecrets.generate()
        val client = repository.save(
            OidcClientEntity(
                id = UUID.randomUUID(),
                tenantId = request.tenantId,
                name = request.name,
                clientSecretHash = secretHasher.hash(secret),
                redirectUris = request.redirectUris.toRedirectUrisCsv(),
                launchUrl = request.launchUrl,
            ),
        )

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = client.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-tenant-svc",
                action = "oidc_client.created",
                result = AuditResult.SUCCESS,
            ),
        )

        return client to secret
    }

    fun getClient(id: UUID): OidcClientEntity =
        repository.findById(id).orElseThrow { OidcClientNotFoundException(id) }

    // Added for Service 14 (iam-admin-console).
    fun listClients(tenantId: UUID): List<OidcClientEntity> =
        repository.findByTenantId(tenantId)

    // Added for group-based launchpad visibility (2026-10-23): every client
    // currently assigned to this one group. A user belongs to at most one
    // group (iam-identity-svc's single-group-per-user shape), so MyAppsController
    // only ever calls this with one groupId at a time -- no need for an
    // IN-list variant yet.
    fun listClientsForGroup(groupId: UUID): List<OidcClientEntity> {
        val clientIds = groupRepository.findByGroupId(groupId).map { it.oidcClientId }
        return if (clientIds.isEmpty()) emptyList() else repository.findAllById(clientIds)
    }

    fun getGroupIds(clientId: UUID): List<UUID> {
        if (!repository.existsById(clientId)) throw OidcClientNotFoundException(clientId)
        return groupRepository.findByOidcClientId(clientId).map { it.groupId }
    }

    // Replace-all semantics: the admin console always sends the full
    // desired set, same as how a multi-select checkbox list naturally
    // works -- simpler than diffing add/remove client-side.
    @Transactional
    fun setGroups(clientId: UUID, groupIds: List<UUID>) {
        if (!repository.existsById(clientId)) throw OidcClientNotFoundException(clientId)
        groupRepository.deleteByOidcClientId(clientId)
        groupRepository.saveAll(groupIds.distinct().map { OidcClientGroupEntity(UUID.randomUUID(), clientId, it) })
    }

    // Same enumeration-safe shape as iam-identity-svc's verifyPassword
    // (Service 7): "no such client" and "wrong secret" must be
    // indistinguishable to the caller.
    fun verifySecret(id: UUID, request: VerifyClientSecretRequest): VerifyClientSecretResponse {
        val client = repository.findById(id).orElse(null) ?: return VerifyClientSecretResponse(valid = false)
        return if (secretHasher.matches(request.clientSecret, client.clientSecretHash)) {
            VerifyClientSecretResponse(valid = true, tenantId = client.tenantId)
        } else {
            VerifyClientSecretResponse(valid = false)
        }
    }
}
