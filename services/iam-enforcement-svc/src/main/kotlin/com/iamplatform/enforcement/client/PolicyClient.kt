package com.iamplatform.enforcement.client

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.util.UUID

data class EvaluateRequest(val tenantId: UUID, val userId: UUID? = null, val country: String)
data class EvaluateResponse(val allowed: Boolean, val reason: String? = null, val policyScopeApplied: String? = null)

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

    fun evaluate(tenantId: UUID, userId: UUID, country: String): EvaluateResponse =
        client.post("/api/v1/evaluate", EvaluateRequest(tenantId, userId, country), EvaluateResponse::class.java)
}
