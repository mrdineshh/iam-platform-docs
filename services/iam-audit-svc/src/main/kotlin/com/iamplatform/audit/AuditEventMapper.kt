package com.iamplatform.audit

import com.iamplatform.servicekit.audit.AuditEvent

fun AuditEvent.toEntity(): AuditEventEntity = AuditEventEntity(
    eventId = eventId,
    correlationId = correlationId,
    occurredAt = timestamp,
    tenantId = tenantId,
    actorType = actorType,
    actorId = actorId,
    action = action,
    result = result,
    reason = reason,
    sourceIp = sourceIp,
    geo = geo,
    deviceId = deviceId,
    policyScopeApplied = policyScopeApplied,
)
