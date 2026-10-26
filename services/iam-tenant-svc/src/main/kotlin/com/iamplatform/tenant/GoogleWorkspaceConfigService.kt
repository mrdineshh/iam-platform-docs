package com.iamplatform.tenant

import com.iamplatform.servicekit.vault.OpenBaoClient
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class GoogleWorkspaceConfigService(
    private val repository: GoogleWorkspaceConfigRepository,
    private val tenantRepository: TenantRepository,
    private val openBaoClient: OpenBaoClient,
) {
    fun setConfig(request: SetGoogleWorkspaceConfigRequest): GoogleWorkspaceConfigEntity {
        if (!tenantRepository.existsById(request.tenantId)) {
            throw TenantNotFoundException(request.tenantId)
        }
        val key = parseServiceAccountJson(request.serviceAccountJson)

        // OpenBao-held, never in Postgres -- same "write-only credential"
        // pattern as every other secret in this system (password pepper,
        // TOTP DEKs, the SAML signing key).
        openBaoClient.writeSecret(
            "google-workspace/${request.tenantId}",
            mapOf(
                "clientEmail" to key.clientEmail,
                "privateKey" to key.privateKey,
                "privateKeyId" to key.privateKeyId,
            ),
        )

        val existing = repository.findByTenantId(request.tenantId)
        val entity = existing?.apply {
            domain = request.domain
            adminEmail = request.adminEmail
            orgUnitPath = request.orgUnitPath
        } ?: GoogleWorkspaceConfigEntity(
            id = UUID.randomUUID(),
            tenantId = request.tenantId,
            domain = request.domain,
            adminEmail = request.adminEmail,
            orgUnitPath = request.orgUnitPath,
        )
        return repository.save(entity)
    }

    fun getConfig(tenantId: UUID): GoogleWorkspaceConfigEntity? = repository.findByTenantId(tenantId)

    /**
     * Returns null if this tenant has no Google Workspace integration
     * configured -- callers (AdminUserController) treat that as "skip
     * provisioning," never as an error. Reconstructs the service account
     * key from OpenBao on every call rather than caching it in memory --
     * user creation is infrequent enough that this isn't a hot path.
     */
    fun loadProvisioningConfig(tenantId: UUID): ProvisionGoogleUserRequest? {
        val config = repository.findByTenantId(tenantId) ?: return null
        val secret = openBaoClient.readSecretOrNull("google-workspace/$tenantId") ?: return null
        val key = GoogleServiceAccountKey(
            clientEmail = secret["clientEmail"] as String,
            privateKey = secret["privateKey"] as String,
            privateKeyId = secret["privateKeyId"] as String,
        )
        return ProvisionGoogleUserRequest(
            domain = config.domain,
            adminEmail = config.adminEmail,
            orgUnitPath = config.orgUnitPath,
            serviceAccountKey = key,
            primaryEmail = "",
            givenName = "",
            familyName = "",
        )
    }

    // Hand-rolled extraction rather than a full JSON parse: a service
    // account key file is always a flat object of string fields (no
    // nesting), so pulling out exactly the three fields needed by regex is
    // simpler and avoids any dependency on which Jackson major version/API
    // shape is active. private_key's value contains literal "\n" escape
    // sequences, which GoogleWorkspaceDirectoryClient.parsePrivateKey
    // already strips before base64-decoding, so they're left as-is here.
    private fun parseServiceAccountJson(json: String): GoogleServiceAccountKey {
        val clientEmail = extractField(json, "client_email")
            ?: throw InvalidServiceAccountJsonException("missing \"client_email\"")
        val privateKey = extractField(json, "private_key")
            ?: throw InvalidServiceAccountJsonException("missing \"private_key\"")
        val privateKeyId = extractField(json, "private_key_id")
            ?: throw InvalidServiceAccountJsonException("missing \"private_key_id\"")
        return GoogleServiceAccountKey(clientEmail, privateKey, privateKeyId)
    }

    private fun extractField(json: String, field: String): String? {
        // Unrolled-loop form: the usual (?:[^"\\]|\\.)* alternation recurses
        // once per character in Java's regex engine and overflows the stack
        // on a ~1.7KB private_key value.
        val pattern = Regex("\"$field\"\\s*:\\s*\"([^\"\\\\]*+(?:\\\\.[^\"\\\\]*+)*+)\"")
        return pattern.find(json)?.groupValues?.get(1)
    }
}
