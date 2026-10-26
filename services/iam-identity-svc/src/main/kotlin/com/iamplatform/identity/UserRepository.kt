package com.iamplatform.identity

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface UserRepository : JpaRepository<UserEntity, UUID> {
    fun existsByTenantIdAndEmail(tenantId: UUID, email: String): Boolean
    fun findByTenantIdAndEmail(tenantId: UUID, email: String): UserEntity?

    // Added for the admin-console "Switch to user" picker.
    fun findByTenantId(tenantId: UUID): List<UserEntity>
}
