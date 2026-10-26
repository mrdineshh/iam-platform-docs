package com.iamplatform.enforcement.client

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.util.LinkedMultiValueMap
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestClient
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

data class GatewayUserInfo(val sub: String, val email: String, val tenant_id: String)
data class GatewayTokenResponse(val access_token: String, val id_token: String, val token_type: String, val expires_in: Long)
data class TerminateAccessTokenRequest(val accessToken: String, val reason: String)
data class TerminateAccessTokenResponse(val terminated: Boolean)

class GatewayNotConfiguredException(message: String) : RuntimeException(message)

/**
 * Lets iam-enforcement-svc act as its own OpenID Connect Relying Party --
 * the same role a real third-party app (Grafana, or a real deployed Pulse)
 * would play -- so a plain browser hitting the "/proxy" path prefix with no
 * session can be sent through the platform's existing login flow and come
 * back with a cookie the gateway itself understands, instead of requiring
 * the caller to
 * already hold a raw X-Session-Token. See docs/DECISIONS.md, gateway
 * cookie-login entry. Never used by the pre-existing X-Session-Token header
 * path, which is unchanged.
 */
@Component
class GatewayOidcClient(
    @Value("\${iam.enforcement.proxy.gateway.client-id:}") private val clientId: String,
    @Value("\${iam.enforcement.proxy.gateway.client-secret:}") private val clientSecret: String,
    @Value("\${iam.enforcement.proxy.gateway.oidc-provider-url:}") private val providerUrl: String,
    @Value("\${iam.enforcement.proxy.gateway.base-url:}") private val gatewayBaseUrl: String,
    restClientBuilder: RestClient.Builder,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
) {
    val isConfigured: Boolean
        get() = clientId.isNotBlank() && clientSecret.isNotBlank() && providerUrl.isNotBlank() && gatewayBaseUrl.isNotBlank()

    private val callbackUrl: String get() = "$gatewayBaseUrl/oauth2/callback"

    private val client = ResilientHttpClient(
        resilientRestClientBuilder(restClientBuilder, providerUrl).build(),
        circuitBreakerRegistry,
        retryRegistry,
        "oidc-provider",
    )

    fun buildAuthorizeUrl(state: String): String {
        if (!isConfigured) throw GatewayNotConfiguredException("gateway OIDC client is not configured")
        val query = "response_type=code" +
            "&client_id=$clientId" +
            "&redirect_uri=${encode(callbackUrl)}" +
            "&scope=openid" +
            "&state=${encode(state)}"
        return "$providerUrl/authorize?$query"
    }

    fun exchangeCode(code: String): GatewayTokenResponse {
        val form = LinkedMultiValueMap<String, String>().apply {
            add("grant_type", "authorization_code")
            add("code", code)
            add("redirect_uri", callbackUrl)
            add("client_id", clientId)
            add("client_secret", clientSecret)
        }
        return client.post("/token", form, GatewayTokenResponse::class.java)
    }

    /** Returns null for an expired/invalid/already-killed access token -- never treated as a transport error. */
    fun userInfo(accessToken: String): GatewayUserInfo? =
        try {
            client.get("/userinfo", GatewayUserInfo::class.java, headers = mapOf("Authorization" to "Bearer $accessToken"))
        } catch (ex: HttpClientErrorException) {
            null
        }

    fun terminate(accessToken: String, reason: String) {
        client.post(
            "/internal/access-tokens/terminate",
            TerminateAccessTokenRequest(accessToken, reason),
            TerminateAccessTokenResponse::class.java,
        )
    }

    private fun encode(value: String) = URLEncoder.encode(value, StandardCharsets.UTF_8)
}
