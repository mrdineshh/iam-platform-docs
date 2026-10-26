package com.iamplatform.tenant

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface SamlSpRepository : JpaRepository<SamlSpEntity, UUID> {
    fun findByTenantId(tenantId: UUID): List<SamlSpEntity>

    fun findBySpEntityId(spEntityId: String): SamlSpEntity?

    fun existsBySpEntityId(spEntityId: String): Boolean
}
