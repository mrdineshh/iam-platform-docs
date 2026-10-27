package com.iamplatform.identity

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.transaction.annotation.Transactional
import java.util.UUID

interface UserRepository : JpaRepository<UserEntity, UUID> {
    fun existsByTenantIdAndEmail(tenantId: UUID, email: String): Boolean
    fun findByTenantIdAndEmail(tenantId: UUID, email: String): UserEntity?

    // Added for the admin-console "Switch to user" picker.
    fun findByTenantId(tenantId: UUID): List<UserEntity>

    // Added so deleting a group can unassign its members first (2026-10-27).
    fun findByGroupId(groupId: UUID): List<UserEntity>

    // Atomic in the database, so concurrent wrong guesses can't lose counts and
    // slip under the lockout threshold with a read-modify-write race.
    @Modifying
    @Transactional
    @Query("update UserEntity u set u.failedLoginAttempts = u.failedLoginAttempts + 1 where u.id = :id")
    fun incrementFailedAttempts(@Param("id") id: UUID): Int
}
