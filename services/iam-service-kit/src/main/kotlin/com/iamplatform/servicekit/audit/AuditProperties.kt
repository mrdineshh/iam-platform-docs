package com.iamplatform.servicekit.audit

import org.springframework.boot.context.properties.ConfigurationProperties

@ConfigurationProperties(prefix = "iam.audit")
data class AuditProperties(
    val topic: String = "audit-events",
)
