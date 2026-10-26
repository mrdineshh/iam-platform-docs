package com.iamplatform.servicekit.audit

import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class AuditEventTest {

    @Test
    fun `each event gets its own eventId by default`() {
        val tenantId = UUID.randomUUID()
        fun newEvent() = AuditEvent(
            correlationId = "corr-1",
            tenantId = tenantId,
            actorType = ActorType.SYSTEM,
            actorId = "svc",
            action = "tenant.created",
            result = AuditResult.SUCCESS,
        )
        assertNotEquals(newEvent().eventId, newEvent().eventId)
    }

    @Test
    fun `audit topic defaults to audit-events`() {
        assertEquals("audit-events", AuditProperties().topic)
    }
}
