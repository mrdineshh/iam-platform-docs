package com.iamplatform.servicekit.vault

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.RestClient

@ConfigurationProperties(prefix = "iam.openbao")
data class OpenBaoProperties(
    val address: String = "http://openbao:8200",
    val token: String = "",
    val kvMount: String = "secret",
)

/**
 * Minimal client for the OpenBao KV v2 secrets engine. No hardcoded secrets
 * anywhere else per Guardrails Section 4 — every service reads its config
 * (DB credentials, signing keys, pepper values, etc.) through this.
 */
class OpenBaoClient(
    private val restClient: RestClient,
    private val properties: OpenBaoProperties,
) {
    fun readSecret(path: String): Map<String, Any?> {
        val response = restClient.get()
            .uri("/v1/${properties.kvMount}/data/$path")
            .header("X-Vault-Token", properties.token)
            .retrieve()
            .body(KvV2Response::class.java)
            ?: throw IllegalStateException("OpenBao returned no body for secret path '$path'")

        return response.data.data
    }

    /** Like [readSecret], but returns null instead of throwing when the path doesn't exist yet. */
    fun readSecretOrNull(path: String): Map<String, Any?>? =
        try {
            readSecret(path)
        } catch (ex: HttpClientErrorException.NotFound) {
            null
        }

    /** Get-or-create callers (e.g. a lazily-provisioned pepper) build on this. */
    fun writeSecret(path: String, data: Map<String, Any?>) {
        restClient.post()
            .uri("/v1/${properties.kvMount}/data/$path")
            .header("X-Vault-Token", properties.token)
            .body(mapOf("data" to data))
            .retrieve()
            .toBodilessEntity()
    }

    private data class KvV2Response(val data: KvV2Data)
    private data class KvV2Data(val data: Map<String, Any?>)

    companion object {
        fun restClientFor(properties: OpenBaoProperties): RestClient =
            RestClient.builder().baseUrl(properties.address).build()
    }
}
