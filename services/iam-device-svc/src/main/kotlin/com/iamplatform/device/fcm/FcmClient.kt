package com.iamplatform.device.fcm

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.util.UUID

class FcmSendFailedException(cause: Throwable) : RuntimeException("Failed to send FCM push", cause)

/**
 * Plain REST call to FCM's HTTP v1 send endpoint (Guardrails Tier-3
 * decision, confirmed with product owner 2026-09-16: use
 * google-auth-library-oauth2-http only for the OAuth2 token exchange, not
 * the full firebase-admin SDK). Wrapped in the same circuit-breaker/retry
 * pattern as every other outbound call to a dependency outside the
 * platform's control (Guardrails Section 2).
 */
@Component
class FcmClient(
    @Value("\${iam.fcm.project-id}") private val projectId: String,
    restClientBuilder: RestClient.Builder,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
    private val credentialsProvider: FcmCredentialsProvider,
) {
    private val client = ResilientHttpClient(
        resilientRestClientBuilder(restClientBuilder, "https://fcm.googleapis.com").build(),
        circuitBreakerRegistry,
        retryRegistry,
        "fcm",
    )

    fun sendPushChallenge(fcmToken: String, challengeId: UUID) {
        try {
            val accessToken = credentialsProvider.get().refreshAccessToken().tokenValue
            client.post(
                "/v1/projects/$projectId/messages:send",
                mapOf(
                    "message" to mapOf(
                        "token" to fcmToken,
                        "data" to mapOf(
                            "type" to "mfa_push",
                            "challengeId" to challengeId.toString(),
                        ),
                    ),
                ),
                Map::class.java,
                headers = mapOf("Authorization" to "Bearer $accessToken"),
            )
        } catch (ex: Exception) {
            throw FcmSendFailedException(ex)
        }
    }
}
