package com.iamplatform.audit

import org.apache.kafka.common.TopicPartition
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.kafka.core.KafkaTemplate
import org.springframework.kafka.listener.CommonErrorHandler
import org.springframework.kafka.listener.DeadLetterPublishingRecoverer
import org.springframework.kafka.listener.DefaultErrorHandler
import org.springframework.kafka.support.ExponentialBackOffWithMaxRetries

/**
 * Guardrails Section 2: exponential backoff with jitter, capped at a
 * configurable max attempt count (default 5), then dead-letter — never a
 * silent drop. audit-events-dlq is a real topic, not a suffix Spring Kafka
 * invents on its own, per BUILD_PLAN.md Section 6, Service 1.
 */
@Configuration
class KafkaConsumerConfig(
    private val properties: AuditKafkaDlqProperties,
) {

    @Bean
    fun kafkaErrorHandler(kafkaTemplate: KafkaTemplate<String, String>): CommonErrorHandler {
        val recoverer = DeadLetterPublishingRecoverer(kafkaTemplate) { _, _ ->
            TopicPartition(properties.dlqTopic, 0)
        }
        val backOff = ExponentialBackOffWithMaxRetries(properties.maxAttempts).apply {
            initialInterval = 1000L
            multiplier = 2.0
            maxInterval = 30_000L
        }
        return DefaultErrorHandler(recoverer, backOff)
    }
}
