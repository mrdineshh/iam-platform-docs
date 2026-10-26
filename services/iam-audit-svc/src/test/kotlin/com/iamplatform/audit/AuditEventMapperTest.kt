package com.iamplatform.audit

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditResult
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals

class AuditEventMapperTest {

    @Test
    fun `toEntity copies every field across`() {
        val tenantId = UUID.randomUUID()
        val event = AuditEvent(
            correlationId = "corr-1",
            tenantId = tenantId,
            actorType = ActorType.ADMIN,
            actorId = "admin-1",
            action = "tenant.created",
            result = AuditResult.SUCCESS,
            reason = "n/a",
            sourceIp = "1.2.3.4",
            geo = "IN",
            deviceId = "device-1",
            policyScopeApplied = "TENANT",
        )

        val entity = event.toEntity()

        assertEquals(event.eventId, entity.eventId)
        assertEquals(event.correlationId, entity.correlationId)
        assertEquals(event.timestamp, entity.occurredAt)
        assertEquals(event.tenantId, entity.tenantId)
        assertEquals(event.actorType, entity.actorType)
        assertEquals(event.actorId, entity.actorId)
        assertEquals(event.action, entity.action)
        assertEquals(event.result, entity.result)
        assertEquals(event.reason, entity.reason)
        assertEquals(event.sourceIp, entity.sourceIp)
        assertEquals(event.geo, entity.geo)
        assertEquals(event.deviceId, entity.deviceId)
        assertEquals(event.policyScopeApplied, entity.policyScopeApplied)
    }
}
