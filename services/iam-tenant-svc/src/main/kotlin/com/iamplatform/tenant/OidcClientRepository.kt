package com.iamplatform.tenant

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface OidcClientRepository : JpaRepository<OidcClientEntity, UUID> {
    // Added for Service 14 (iam-admin-console).
    fun findByTenantId(tenantId: UUID): List<OidcClientEntity>
}
