package com.iamplatform.audit

import com.iamplatform.servicekit.audit.AuditEvent
import org.slf4j.LoggerFactory
import org.springframework.kafka.annotation.KafkaListener
import org.springframework.stereotype.Component
import tools.jackson.databind.ObjectMapper

/**
 * iam-audit-svc has no outbound calls to any other service — it is safe to
 * build first in BUILD_PLAN.md's Section 6 order because nothing else needs
 * to exist for it to work. Any exception thrown out of [onMessage] is handled
 * by the container's error handler (see KafkaConsumerConfig): retried with
 * backoff, then routed to audit-events-dlq if still failing, never dropped
 * silently (Guardrails Section 2).
 */
@Component
class AuditEventConsumer(
    private val repository: AuditEventRepository,
    private val objectMapper: ObjectMapper,
) {
    private val log = LoggerFactory.getLogger(AuditEventConsumer::class.java)

    @KafkaListener(topics = ["\${iam.audit.topic:audit-events}"], groupId = "iam-audit-svc")
    fun onMessage(payload: String) {
        val event = objectMapper.readValue(payload, AuditEvent::class.java)

        if (repository.existsById(event.eventId)) {
            log.info("Skipping already-processed audit event {} (idempotent retry/redelivery)", event.eventId)
            return
        }

        repository.save(event.toEntity())
        log.debug("Persisted audit event {} action={} correlationId={}", event.eventId, event.action, event.correlationId)
    }
}
