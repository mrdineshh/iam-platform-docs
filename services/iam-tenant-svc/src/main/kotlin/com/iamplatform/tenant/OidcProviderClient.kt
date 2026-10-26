package com.iamplatform.tenant

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient

data class RemoteSamlIdpInfo(val entityId: String, val ssoUrl: String, val certificatePem: String)

/**
 * Only used to proxy iam-oidcprovider-svc's SAML IdP metadata (entity ID,
 * SSO URL, signing certificate) through to admin-console's browser --
 * iam-oidcprovider-svc has no CORS config (nothing else calls it directly
 * from a browser), so this service-to-service hop is the path, same
 * reasoning as every other internal-only lookup in this codebase.
 */
@Component
class OidcProviderClient(
    @Value("\${iam.dependencies.oidcprovider-svc}") baseUrl: String,
    restClientBuilder: RestClient.Builder,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
) {
    private val client = ResilientHttpClient(
        resilientRestClientBuilder(restClientBuilder, baseUrl).build(),
        circuitBreakerRegistry,
        retryRegistry,
        "oidcprovider-svc",
    )

    fun samlIdpInfo(): RemoteSamlIdpInfo =
        client.get("/saml/idp-info", RemoteSamlIdpInfo::class.java)
}
