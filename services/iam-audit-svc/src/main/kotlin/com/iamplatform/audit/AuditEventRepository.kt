package com.iamplatform.audit

import org.springframework.data.jpa.repository.JpaRepository
import java.util.UUID

interface AuditEventRepository : JpaRepository<AuditEventEntity, UUID>
