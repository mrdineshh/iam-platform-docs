package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import com.iamplatform.servicekit.vault.OpenBaoClient
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import org.springframework.stereotype.Service
import java.time.Instant
import java.util.UUID

class ScimConnectionNotFoundException(id: UUID) : RuntimeException("No provisioning connection '$id' for this tenant")

data class UpsertScimConnectionRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    @field:Pattern(regexp = "^(OIDC|SAML)$", message = "must be OIDC or SAML")
    val appKind: String,

    @field:NotNull
    val appId: UUID,

    @field:NotBlank
    @field:Size(max = 1024)
    val baseUrl: String,

    // Required when the connection is first created; optional afterwards
    // (blank keeps the stored token). Write-only: never returned.
    @field:Size(max = 2048)
    val bearerToken: String? = null,

    val enabled: Boolean = true,
)

data class ScimConnectionView(
    val id: UUID,
    val appKind: String,
    val appId: UUID,
    val appName: String,
    val baseUrl: String,
    val enabled: Boolean,
    val hasToken: Boolean,
    val accountsActive: Int,
    val accountsSuspended: Int,
    val accountsFailed: Int,
)

data class ConnectionTestResult(val ok: Boolean, val message: String)

/** Per-user, per-app state shown to admins (and what "Retry" acts on). */
data class UserProvisioningStatus(
    val connectionId: UUID,
    val appName: String,
    // NOT_PROVISIONED | PENDING | ACTIVE | SUSPENDED
    val state: String,
    val error: String?,
    val updatedAt: Instant?,
)

@Service
class ScimConnectionService(
    private val connections: ScimConnectionRepository,
    private val accounts: ProvisionedAccountRepository,
    private val tenantRepository: TenantRepository,
    private val oidcClients: OidcClientRepository,
    private val samlSps: SamlSpRepository,
    private val provisioning: ProvisioningService,
    private val scim: ScimClient,
    private val urlGuard: OutboundUrlGuard,
    private val openBaoClient: OpenBaoClient,
    private val auditPublisher: AuditPublisher,
) {
    fun list(tenantId: UUID): List<ScimConnectionView> =
        connections.findByTenantId(tenantId).sortedBy { provisioning.appName(it) }.map { view(it) }

    fun upsert(request: UpsertScimConnectionRequest, adminId: UUID): ScimConnectionView {
        if (!tenantRepository.existsById(request.tenantId)) throw TenantNotFoundException(request.tenantId)
        requireAppInTenant(request.tenantId, request.appKind, request.appId)
        // Rejects non-https and internal addresses before anything is stored.
        val baseUrl = urlGuard.validate(request.baseUrl).toString().trimEnd('/')

        val existing = connections.findByTenantIdAndAppKindAndAppId(request.tenantId, request.appKind, request.appId)
        val token = request.bearerToken?.trim()?.takeIf { it.isNotEmpty() }
        if (existing == null && token == null) {
            throw InvalidProvisioningTargetException("An access token is required to connect an app.")
        }

        val connection = (existing ?: ScimConnectionEntity(UUID.randomUUID(), request.tenantId, request.appKind, request.appId, baseUrl))
            .apply {
                this.baseUrl = baseUrl
                this.enabled = request.enabled
                this.updatedAt = Instant.now()
            }
        // OpenBao-held, never in Postgres, like every other credential here. Stored first:
        // if the secret store refuses, nothing is saved, so there is never a connection without its token.
        if (token != null) openBaoClient.writeSecret("scim/${connection.id}", mapOf("token" to token))
        val saved = connections.save(connection)

        audit(request.tenantId, adminId, "provisioning.connection_saved", "app=${provisioning.appName(saved)}; enabled=${saved.enabled}")
        return view(saved)
    }

    fun delete(tenantId: UUID, connectionId: UUID, adminId: UUID) {
        val connection = require(tenantId, connectionId)
        val name = provisioning.appName(connection)
        // OpenBao has no delete in our client; blanking the token makes it unusable.
        openBaoClient.writeSecret("scim/${connection.id}", mapOf("token" to ""))
        connections.delete(connection)
        audit(tenantId, adminId, "provisioning.connection_removed", "app=$name")
    }

    fun test(tenantId: UUID, connectionId: UUID): ConnectionTestResult {
        val connection = require(tenantId, connectionId)
        val token = provisioning.tokenFor(connection)
        if (token.isNullOrBlank()) return ConnectionTestResult(false, "No access token is stored. Save the connection again with a token.")
        return try {
            scim.testConnection(connection.baseUrl, token)
            ConnectionTestResult(true, "Connected. The app's SCIM endpoint answered.")
        } catch (ex: ScimException) {
            ConnectionTestResult(false, ex.message ?: "The app returned an error.")
        }
    }

    fun sync(tenantId: UUID, connectionId: UUID, adminId: UUID): SyncSummary {
        val connection = require(tenantId, connectionId)
        val summary = provisioning.syncConnection(connection)
        audit(
            tenantId, adminId, "provisioning.connection_synced",
            "app=${provisioning.appName(connection)}; users=${summary.users}; ok=${summary.succeeded}; failed=${summary.failed}",
        )
        return summary
    }

    fun statusForUser(tenantId: UUID, userId: UUID): List<UserProvisioningStatus> =
        connections.findByTenantId(tenantId).sortedBy { provisioning.appName(it) }.map { c ->
            val account = accounts.findByUserIdAndConnectionId(userId, c.id)
            UserProvisioningStatus(
                connectionId = c.id,
                appName = provisioning.appName(c),
                state = account?.state ?: "NOT_PROVISIONED",
                error = account?.lastError,
                updatedAt = account?.updatedAt,
            )
        }

    private fun view(c: ScimConnectionEntity): ScimConnectionView {
        val rows = accounts.findByConnectionId(c.id)
        return ScimConnectionView(
            id = c.id,
            appKind = c.appKind,
            appId = c.appId,
            appName = provisioning.appName(c),
            baseUrl = c.baseUrl,
            enabled = c.enabled,
            hasToken = !provisioning.tokenFor(c).isNullOrBlank(),
            accountsActive = rows.count { it.state == AccountState.ACTIVE.name && it.lastError == null },
            accountsSuspended = rows.count { it.state == AccountState.SUSPENDED.name && it.lastError == null },
            accountsFailed = rows.count { it.lastError != null },
        )
    }

    private fun require(tenantId: UUID, connectionId: UUID): ScimConnectionEntity =
        connections.findById(connectionId).filter { it.tenantId == tenantId }.orElseThrow { ScimConnectionNotFoundException(connectionId) }

    private fun requireAppInTenant(tenantId: UUID, appKind: String, appId: UUID) {
        val appTenant = when (appKind) {
            "OIDC" -> oidcClients.findById(appId).map { it.tenantId }.orElse(null)
            else -> samlSps.findById(appId).map { it.tenantId }.orElse(null)
        }
        if (appTenant != tenantId) throw InvalidProvisioningTargetException("That app does not exist for this tenant.")
    }

    private fun audit(tenantId: UUID, adminId: UUID, action: String, reason: String) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.ADMIN,
                actorId = adminId.toString(),
                action = action,
                result = AuditResult.SUCCESS,
                reason = reason,
            ),
        )
    }
}
