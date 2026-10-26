package com.iamplatform.servicekit.autoconfigure

import com.iamplatform.servicekit.audit.AuditProperties
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.KafkaAuditPublisher
import com.iamplatform.servicekit.correlation.CorrelationIdFilter
import com.iamplatform.servicekit.vault.OpenBaoClient
import com.iamplatform.servicekit.vault.OpenBaoProperties
import org.springframework.boot.autoconfigure.AutoConfiguration
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.kafka.core.KafkaTemplate
import tools.jackson.databind.ObjectMapper

/**
 * Wires the shared technical infra (correlation IDs, audit publishing,
 * OpenBao client) into every service that depends on iam-service-kit,
 * without any service having to configure it by hand. Domain code stays
 * out of this module per BUILD_PLAN.md Section 4.5.
 */
@AutoConfiguration
@EnableConfigurationProperties(AuditProperties::class, OpenBaoProperties::class)
class ServiceKitAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    fun correlationIdFilter(): CorrelationIdFilter = CorrelationIdFilter()

    @Bean
    @ConditionalOnMissingBean
    fun auditPublisher(
        kafkaTemplate: KafkaTemplate<String, String>,
        objectMapper: ObjectMapper,
        properties: AuditProperties,
    ): AuditPublisher = KafkaAuditPublisher(kafkaTemplate, objectMapper, properties)

    @Bean
    @ConditionalOnMissingBean
    fun openBaoClient(properties: OpenBaoProperties): OpenBaoClient =
        OpenBaoClient(OpenBaoClient.restClientFor(properties), properties)
}
