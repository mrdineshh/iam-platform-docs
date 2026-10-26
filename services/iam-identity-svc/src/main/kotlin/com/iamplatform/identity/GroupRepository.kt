package com.iamplatform.identity

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface GroupRepository : JpaRepository<GroupEntity, UUID> {
    fun findByTenantId(tenantId: UUID): List<GroupEntity>
}
