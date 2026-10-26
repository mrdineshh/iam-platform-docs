package com.iamplatform.servicekit.http

import com.iamplatform.servicekit.correlation.CorrelationId
import io.github.resilience4j.circuitbreaker.CircuitBreaker
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry
import io.github.resilience4j.retry.Retry
import io.github.resilience4j.retry.RetryRegistry
import org.springframework.http.client.JdkClientHttpRequestFactory
import org.springframework.web.client.RestClient
import java.net.http.HttpClient
import java.time.Duration

/**
 * Every outbound inter-service call goes through one of these, never a bare
 * RestClient. Circuit breaker + retry instance names come from the caller
 * (matching a named instance in application.yml's resilience4j config, or
 * "default" per BUILD_PLAN.md Section 7's sample). Timeouts are set on the
 * underlying request factory (see [resilientRestClientBuilder]) rather than
 * via Resilience4j's TimeLimiter, which targets async call shapes — RestClient
 * here is synchronous, so a bounded connect/read timeout is what actually
 * prevents an unbounded wait (Guardrails Section 2).
 */
class ResilientHttpClient(
    private val restClient: RestClient,
    circuitBreakerRegistry: CircuitBreakerRegistry,
    retryRegistry: RetryRegistry,
    instanceName: String,
) {
    private val circuitBreaker: CircuitBreaker = circuitBreakerRegistry.circuitBreaker(instanceName)
    private val retry: Retry = retryRegistry.retry(instanceName)

    fun <T : Any> get(uri: String, responseType: Class<T>, headers: Map<String, String> = emptyMap()): T = execute {
        val request = restClient.get()
            .uri(uri)
            .header(CorrelationId.HEADER, CorrelationId.get())
        headers.forEach { (key, value) -> request.header(key, value) }
        request.retrieve().body(responseType)!!
    }

    fun <T : Any> post(uri: String, body: Any, responseType: Class<T>, headers: Map<String, String> = emptyMap()): T = execute {
        val request = restClient.post()
            .uri(uri)
            .header(CorrelationId.HEADER, CorrelationId.get())
        headers.forEach { (key, value) -> request.header(key, value) }
        request.body(body).retrieve().body(responseType)!!
    }

    fun <T : Any> patch(uri: String, body: Any, responseType: Class<T>, headers: Map<String, String> = emptyMap()): T = execute {
        val request = restClient.patch()
            .uri(uri)
            .header(CorrelationId.HEADER, CorrelationId.get())
        headers.forEach { (key, value) -> request.header(key, value) }
        request.body(body).retrieve().body(responseType)!!
    }

    fun delete(uri: String, headers: Map<String, String> = emptyMap()): Unit = execute {
        val request = restClient.delete()
            .uri(uri)
            .header(CorrelationId.HEADER, CorrelationId.get())
        headers.forEach { (key, value) -> request.header(key, value) }
        request.retrieve().toBodilessEntity()
        Unit
    }

    private fun <T> execute(call: () -> T): T {
        val decorated = Retry.decorateSupplier(retry, CircuitBreaker.decorateSupplier(circuitBreaker, call))
        return decorated.get()
    }
}

/**
 * Builds a RestClient with an explicit, bounded connect/read timeout — no
 * inter-service call may rely on an unbounded default.
 *
 * Callers must pass Spring's own autoconfigured, prototype-scoped
 * `RestClient.Builder` bean (constructor-inject `RestClient.Builder`), not a
 * fresh `RestClient.builder()`. Only the autoconfigured builder carries the
 * `ObservationRestClientCustomizer` that creates outbound HTTP client spans
 * and propagates trace context (`traceparent`) onto the request -- a bare
 * builder silently produces uninstrumented, uncorrelated calls. Found while
 * verifying Service 7's TEST GATE: every prior client (TenantClient,
 * IdentityClient, GeoClient, PolicyClient, SessionClient) had this bug until
 * this fix (see docs/DECISIONS.md, Service 7 entry).
 */
fun resilientRestClientBuilder(
    builder: RestClient.Builder,
    baseUrl: String,
    connectTimeout: Duration = Duration.ofSeconds(2),
    readTimeout: Duration = Duration.ofSeconds(5),
): RestClient.Builder {
    val httpClientBuilder = HttpClient.newBuilder()
        .connectTimeout(connectTimeout)
    // Presents this service's internal mTLS cert and trusts the platform CA
    // on every outbound call, automatically, whenever the entrypoint script
    // provisioned one -- see MtlsSslContext. No-op (plain HTTP, unchanged)
    // for a service with no cert files, e.g. iam-audit-svc.
    MtlsSslContext.instance?.let { httpClientBuilder.sslContext(it) }
    val httpClient = httpClientBuilder.build()
    val requestFactory = JdkClientHttpRequestFactory(httpClient).apply {
        setReadTimeout(readTimeout)
    }
    return builder
        .baseUrl(baseUrl)
        .requestFactory(requestFactory)
}
