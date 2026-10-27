package com.iamplatform.identity

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.util.UUID

/** A tenant's effective sign-in security settings (FR-3.1, FR-3.5), defaults already applied. lockoutThreshold 0 = off. */
data class SecuritySettings(
    val passwordMinLength: Int,
    val passwordRequireUppercase: Boolean,
    val passwordRequireLowercase: Boolean,
    val passwordRequireDigit: Boolean,
    val passwordRequireSymbol: Boolean,
    val lockoutThreshold: Int,
    val lockoutDurationMinutes: Int,
    val lockoutPermanent: Boolean,
)

/**
 * Reads the tenant's password and lockout settings from iam-policy-svc, the
 * single place that configuration lives (AP-1). Read-only; this service never
 * stores policy itself.
 */
@Component
class PolicyClient(
    @Value("\${iam.dependencies.policy-svc}") baseUrl: String,
    restClientBuilder: RestClient.Builder,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
) {
    private val client = ResilientHttpClient(
        resilientRestClientBuilder(restClientBuilder, baseUrl).build(),
        circuitBreakerRegistry,
        retryRegistry,
        "policy-svc",
    )

    fun securitySettings(tenantId: UUID): SecuritySettings =
        client.get("/api/v1/security-settings?tenantId=$tenantId", SecuritySettings::class.java)
}
