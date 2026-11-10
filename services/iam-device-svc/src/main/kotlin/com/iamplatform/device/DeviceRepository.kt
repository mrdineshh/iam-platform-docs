package com.iamplatform.device

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface DeviceRepository : JpaRepository<DeviceEntity, UUID> {
    /** "The" device for a tenant/user is always the most recently enrolled one. */
    fun findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(tenantId: UUID, userId: UUID): DeviceEntity?

    fun findFirstByTenantIdAndUserIdAndFcmTokenIsNotNullOrderByCreatedAtDesc(tenantId: UUID, userId: UUID): DeviceEntity?

    /** Admin-triggered "lost phone" reset -- deletes every row for this user (active or pending), not just
     *  the newest, so no stray secret is left behind. Returns how many were deleted (0 is not an error). */
    fun deleteByTenantIdAndUserId(tenantId: UUID, userId: UUID): Long
}
