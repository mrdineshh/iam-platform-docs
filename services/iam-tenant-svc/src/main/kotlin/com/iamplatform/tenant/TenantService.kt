package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class TenantService(
    private val repository: TenantRepository,
    private val auditPublisher: AuditPublisher,
) {

    fun createTenant(request: CreateTenantRequest): TenantEntity {
        if (repository.existsBySubdomain(request.subdomain)) {
            throw SubdomainAlreadyExistsException(request.subdomain)
        }

        val tenant = repository.save(
            TenantEntity(
                id = UUID.randomUUID(),
                name = request.name,
                subdomain = request.subdomain,
            ),
        )

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenant.id,
                // No admin/RBAC identity exists yet at this point in the build
                // (iam-auth-svc, Service 7) -- see docs/DECISIONS.md, Service 2 entry.
                actorType = ActorType.SYSTEM,
                actorId = "iam-tenant-svc",
                action = "tenant.created",
                result = AuditResult.SUCCESS,
            ),
        )

        return tenant
    }

    fun getTenant(id: UUID): TenantEntity =
        repository.findById(id).orElseThrow { TenantNotFoundException(id) }

    // Added for Service 13 (iam-login-portal, FR-6.2 subdomain-only tenant
    // resolution) -- see docs/DECISIONS.md, Service 13 pre-implementation entry.
    fun getTenantBySubdomain(subdomain: String): TenantEntity =
        repository.findBySubdomain(subdomain) ?: throw TenantSubdomainNotFoundException(subdomain)
}
