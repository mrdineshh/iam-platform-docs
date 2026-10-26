package com.iamplatform.policy

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface PolicyRepository : JpaRepository<PolicyEntity, UUID> {
    fun findByTenantIdAndScopeAndScopeId(tenantId: UUID, scope: PolicyScope, scopeId: UUID): PolicyEntity?
}
