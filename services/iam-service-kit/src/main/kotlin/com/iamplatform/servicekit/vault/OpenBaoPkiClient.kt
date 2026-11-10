package com.iamplatform.servicekit.vault

import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.web.client.RestClient
import java.time.Instant

/**
 * Standard Vault-compatible PKI secrets engine client (OpenBao implements
 * the same PKI API surface as HashiCorp Vault). Used for device-certificate
 * issuance and revocation -- see the Endpoint Device Trust spec Section 16
 * ("PKI: OpenBao-backed CA/key custody; controlled issuance, renewal,
 * rotation and revocation"). A dedicated client, not folded into
 * OpenBaoClient, because the PKI secrets engine's request/response shape
 * (issue/revoke) is unrelated to that class's KV v2 read/write shape.
 *
 * Setup this depends on (operator-side, not application code): a PKI
 * secrets engine mounted in OpenBao (e.g. at "pki-device") with a CA
 * already generated or an intermediate CSR signed, and at least one role
 * configured for device-certificate issuance (short TTL, no CA basic
 * constraint, client-auth-only extended key usage). Same "a human grants
 * this once, the app never silently works around a missing grant" pattern
 * as every Google domain-wide-delegation scope added to this codebase.
 */
@ConfigurationProperties(prefix = "iam.openbao.pki")
data class PkiProperties(
    val pkiMount: String = "pki-device",
)

data class IssuedCertificate(
    val certificatePem: String,
    val issuingCaPem: String,
    val serialNumber: String,
    val notBefore: Instant,
    val notAfter: Instant,
)

class OpenBaoPkiException(message: String) : RuntimeException(message)

class OpenBaoPkiClient(
    private val restClient: RestClient,
    private val properties: OpenBaoProperties,
    private val pkiProperties: PkiProperties,
) {
    /**
     * Issues a device certificate from OpenBao's PKI role, binding
     * [commonName] (the IAM device_id) and [tenantId]/[deviceId] into the
     * certificate's subject so the PEP can trust the subject fields
     * directly rather than round-tripping to the device registry on every
     * request. [role] is a pre-configured OpenBao PKI role name (e.g.
     * "endpoint-device"), not passed by the caller as free text.
     */
    fun issueCertificate(role: String, commonName: String, tenantId: String, deviceId: String, ttlSeconds: Long): IssuedCertificate {
        val response = try {
            restClient.post()
                .uri("/v1/${pkiProperties.pkiMount}/issue/{role}", role)
                .header("X-Vault-Token", properties.token)
                .body(
                    mapOf(
                        "common_name" to commonName,
                        "ttl" to "${ttlSeconds}s",
                        // Subject alternative name carries the stable IDs the PEP actually needs;
                        // common_name alone isn't guaranteed unique across tenants.
                        "alt_names" to "$deviceId.$tenantId.device.iam-internal",
                    ),
                )
                .retrieve()
                .body(PkiIssueResponse::class.java)
        } catch (ex: Exception) {
            throw OpenBaoPkiException("Device certificate issuance failed: ${ex.message}")
        } ?: throw OpenBaoPkiException("OpenBao PKI engine returned no body for certificate issuance")

        val data = response.data ?: throw OpenBaoPkiException("OpenBao PKI issuance response had no data")
        return IssuedCertificate(
            certificatePem = data.certificate,
            issuingCaPem = data.issuing_ca,
            serialNumber = data.serial_number,
            notBefore = Instant.now(),
            notAfter = Instant.now().plusSeconds(ttlSeconds),
        )
    }

    /** Revokes a previously issued certificate by serial number. Idempotent on OpenBao's side. */
    fun revokeCertificate(serialNumber: String) {
        try {
            restClient.post()
                .uri("/v1/${pkiProperties.pkiMount}/revoke")
                .header("X-Vault-Token", properties.token)
                .body(mapOf("serial_number" to serialNumber))
                .retrieve()
                .toBodilessEntity()
        } catch (ex: Exception) {
            throw OpenBaoPkiException("Device certificate revocation failed: ${ex.message}")
        }
    }

    private data class PkiIssueResponse(val data: PkiIssueData?)
    private data class PkiIssueData(val certificate: String, val issuing_ca: String, val serial_number: String)

    companion object {
        fun restClientFor(properties: OpenBaoProperties): RestClient =
            RestClient.builder().baseUrl(properties.address).build()
    }
}
