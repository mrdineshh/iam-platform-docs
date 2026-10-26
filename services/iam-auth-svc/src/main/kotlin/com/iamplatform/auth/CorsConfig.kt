package com.iamplatform.auth

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Configuration
import org.springframework.web.servlet.config.annotation.CorsRegistry
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer

/**
 * Added for Service 14 (iam-admin-console) -- the first browser-direct
 * caller this service has. iam-login-portal never needed this: its calls
 * to iam-auth-svc happen server-side (Next.js Server Actions), never
 * subject to the browser's same-origin policy. A pure SPA has no server to
 * hide the call behind, so this service must explicitly allow it. No
 * credentials mode (cookies) is used anywhere on this platform -- the
 * session token travels only as an explicit header -- so this is safe to
 * allow without `allowCredentials`.
 */
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
