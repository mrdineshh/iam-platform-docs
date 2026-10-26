package com.iamplatform.policy

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

/** Added for Service 14 (iam-admin-console) -- see iam-auth-svc's CorsConfig.kt for the full rationale. */
@Configuration
class CorsConfig(
    @Value("\${iam.cors.allowed-origins:http://localhost:5173}") private val allowedOrigins: String,
) : WebMvcConfigurer {
    override fun addCorsMappings(registry: CorsRegistry) {
        registry.addMapping("/api/v1/**")
            .allowedOrigins(*allowedOrigins.split(",").map { it.trim() }.toTypedArray())
            .allowedMethods("GET", "POST", "PUT", "PATCH", "DELETE")
            .allowedHeaders("Content-Type", "X-Session-Token", "X-Correlation-Id")
    }
}
