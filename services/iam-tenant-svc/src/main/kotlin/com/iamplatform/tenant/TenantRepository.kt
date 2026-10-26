package com.iamplatform.tenant

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface TenantRepository : JpaRepository<TenantEntity, UUID> {
    fun existsBySubdomain(subdomain: String): Boolean
    fun findBySubdomain(subdomain: String): TenantEntity?
}
