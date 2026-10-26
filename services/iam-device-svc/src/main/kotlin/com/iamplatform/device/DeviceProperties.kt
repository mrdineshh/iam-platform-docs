package com.iamplatform.device

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "iam.device.totp")
data class TotpPolicyProperties(
    val maxFailedAttempts: Int = 5,
    val lockDuration: Duration = Duration.ofMinutes(5),
    val stepSeconds: Long = 30,
    val digits: Int = 6,
    val driftWindowSteps: Int = 1,
)

@ConfigurationProperties(prefix = "iam.device.push")
data class PushPolicyProperties(
    val waitTimeoutSeconds: Long = 60,
    val challengeTtlSeconds: Long = 90,
)
