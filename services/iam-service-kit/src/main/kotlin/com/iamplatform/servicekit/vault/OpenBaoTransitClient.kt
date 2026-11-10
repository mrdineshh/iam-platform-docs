package com.iamplatform.servicekit.vault

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.web.client.RestClient
import java.util.Base64

@ConfigurationProperties(prefix = "iam.openbao.transit")
data class TransitProperties(
    val mount: String = "transit",
)

class OpenBaoTransitException(message: String) : RuntimeException(message)

/**
 * Standard Vault-compatible "transit" secrets engine client: signing as a
 * service. The private signing key never leaves OpenBao and this
 * application never sees it -- callers only ever send data to be signed
 * and get a signature back. Used to sign device-trust policy responses
 * (DevicePolicySigner) so an endpoint agent can verify a policy came from
 * this platform and was not tampered with or rolled back (Endpoint Device
 * Trust spec Section 16, "Policy: signed, versioned, expiry-bound and
 * anti-rollback protected").
 *
 * Setup this depends on (operator-side): a transit secrets engine mounted
 * in OpenBao with a named signing key (e.g. "device-policy"), created with
 * `vault write transit/keys/device-policy type=ed25519` or equivalent.
 */
class OpenBaoTransitClient(
    private val restClient: RestClient,
    private val properties: OpenBaoProperties,
    private val transitProperties: TransitProperties,
) {
    /** Returns OpenBao's own versioned signature string (e.g. "vault:v1:..."), opaque to the caller. */
    fun sign(keyName: String, data: ByteArray): String {
        val response = try {
            restClient.post()
                .uri("/v1/${transitProperties.mount}/sign/{keyName}", keyName)
                .header("X-Vault-Token", properties.token)
                .body(mapOf("input" to Base64.getEncoder().encodeToString(data)))
                .retrieve()
                .body(TransitSignResponse::class.java)
        } catch (ex: Exception) {
            throw OpenBaoTransitException("Signing via OpenBao transit engine failed: ${ex.message}")
        } ?: throw OpenBaoTransitException("OpenBao transit engine returned no body")

        return response.data?.signature ?: throw OpenBaoTransitException("OpenBao transit sign response had no signature")
    }

    private data class TransitSignResponse(val data: TransitSignData?)
    private data class TransitSignData(val signature: String?)

    companion object {
        fun restClientFor(properties: OpenBaoProperties): RestClient =
            RestClient.builder().baseUrl(properties.address).build()
    }
}
