package com.iamplatform.audit

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "iam.audit")
data class AuditKafkaDlqProperties(
    val dlqTopic: String = "audit-events-dlq",
    val maxAttempts: Int = 5,
)
