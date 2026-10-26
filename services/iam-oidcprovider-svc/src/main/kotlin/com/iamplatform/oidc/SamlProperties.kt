package com.iamplatform.oidc

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "iam.saml")
data class SamlProperties(
    val assertionTtl: Duration = Duration.ofMinutes(5),
)
