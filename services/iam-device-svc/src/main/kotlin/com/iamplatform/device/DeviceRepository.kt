package com.iamplatform.device

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface DeviceRepository : JpaRepository<DeviceEntity, UUID> {
    /** "The" device for a tenant/user is always the most recently enrolled one. */
    fun findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(tenantId: UUID, userId: UUID): DeviceEntity?

    fun findFirstByTenantIdAndUserIdAndFcmTokenIsNotNullOrderByCreatedAtDesc(tenantId: UUID, userId: UUID): DeviceEntity?
}
