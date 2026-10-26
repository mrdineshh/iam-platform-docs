package com.iamplatform.tenant

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface GoogleWorkspaceConfigRepository : JpaRepository<GoogleWorkspaceConfigEntity, UUID> {
    fun findByTenantId(tenantId: UUID): GoogleWorkspaceConfigEntity?
}
