package com.iamplatform.servicekit.audit

import com.iamplatform.servicekit.correlation.CorrelationId
import org.slf4j.LoggerFactory
import org.springframework.kafka.core.KafkaTemplate
import org.springframework.kafka.support.KafkaHeaders
import org.springframework.messaging.support.MessageBuilder
import tools.jackson.databind.ObjectMapper
import java.nio.charset.StandardCharsets

/**
 * Every service publishes through this, never touches the Kafka producer
 * directly. Retry/backoff is the Kafka client's own producer config
 * (see application.yml); correlation-ID propagation happens here once,
 * not reimplemented per service, and rides both in the payload and as a
 * Kafka message header per BUILD_PLAN.md Section 4.4.
 *
 * Per Guardrails Section 2: if publish genuinely fails after the producer's
 * own retries are exhausted, this is logged locally (never silently dropped)
 * and rethrown so the caller's own error handling / DLQ semantics apply.
 */
class KafkaAuditPublisher(
    private val kafkaTemplate: KafkaTemplate<String, String>,
    private val objectMapper: ObjectMapper,
    private val properties: AuditProperties,
) : AuditPublisher {

    private val log = LoggerFactory.getLogger(KafkaAuditPublisher::class.java)

    override fun publish(event: AuditEvent) {
        val payload = objectMapper.writeValueAsString(event)
        val message = MessageBuilder
            .withPayload(payload)
            .setHeader(KafkaHeaders.TOPIC, properties.topic)
            .setHeader(KafkaHeaders.KEY, event.tenantId.toString())
            .setHeader("X-Correlation-Id", event.correlationId.toByteArray(StandardCharsets.UTF_8))
            .build()

        kafkaTemplate.send(message).whenComplete { _, ex ->
            if (ex != null) {
                log.error(
                    "Failed to publish audit event {} action={} correlationId={} after producer retries exhausted",
                    event.eventId, event.action, event.correlationId, ex,
                )
            }
        }
    }

    companion object {
        fun currentCorrelationId(): String = CorrelationId.get()
    }
}
