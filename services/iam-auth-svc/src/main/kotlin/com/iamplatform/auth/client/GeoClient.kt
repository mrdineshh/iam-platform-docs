package com.iamplatform.auth.client

import com.iamplatform.servicekit.http.ResilientHttpClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient

data class GeoResolution(
    val ip: String,
    val resolved: Boolean,
    val country: String? = null,
    val region: String? = null,
    val city: String? = null,
)

@Component
class GeoClient(
    @Value("\${iam.dependencies.geo-svc}") baseUrl: String,
    restClientBuilder: RestClient.Builder,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
) {
    private val client = ResilientHttpClient(
        resilientRestClientBuilder(restClientBuilder, baseUrl).build(),
        circuitBreakerRegistry,
        retryRegistry,
        "geo-svc",
    )

    fun resolve(ip: String): GeoResolution =
        client.get("/api/v1/resolve?ip=$ip", GeoResolution::class.java)
}
