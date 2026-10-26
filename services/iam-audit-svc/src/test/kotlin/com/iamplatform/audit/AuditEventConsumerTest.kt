package com.iamplatform.audit

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditResult
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.util.UUID

class AuditEventConsumerTest {

    private val objectMapper = jacksonObjectMapper()

    private fun sampleEvent() = AuditEvent(
        correlationId = "corr-1",
        tenantId = UUID.randomUUID(),
        actorType = ActorType.SYSTEM,
        actorId = "svc",
        action = "tenant.created",
        result = AuditResult.SUCCESS,
    )

    @Test
    fun `persists a new event it has not seen before`() {
        val repository = mock<AuditEventRepository>()
        val consumer = AuditEventConsumer(repository, objectMapper)
        val event = sampleEvent()
        whenever(repository.existsById(event.eventId)).thenReturn(false)

        consumer.onMessage(objectMapper.writeValueAsString(event))

        verify(repository).save(any())
    }

    @Test
    fun `skips a redelivered event instead of failing or double-writing`() {
        val repository = mock<AuditEventRepository>()
        val consumer = AuditEventConsumer(repository, objectMapper)
        val event = sampleEvent()
        whenever(repository.existsById(event.eventId)).thenReturn(true)

        consumer.onMessage(objectMapper.writeValueAsString(event))

        verify(repository, never()).save(any())
    }
}
