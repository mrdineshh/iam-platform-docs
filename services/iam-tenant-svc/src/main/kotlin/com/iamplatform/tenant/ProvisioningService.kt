package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import com.iamplatform.servicekit.vault.OpenBaoClient
import org.springframework.stereotype.Service
import java.time.Instant
import java.util.UUID

/** The slice of a user that provisioning needs. `active` mirrors the platform status (ACTIVE = true). */
data class ProvisionUser(
    val id: UUID,
    val tenantId: UUID,
    val email: String,
    val displayName: String,
    val active: Boolean,
)

/** Outcome for one target (an app, or Google Workspace) of one lifecycle change. */
data class TargetResult(
    val target: String,
    // created | linked | suspended | reactivated | deleted | unchanged | skipped | failed
    val action: String,
    val ok: Boolean,
    val error: String? = null,
)

data class SyncSummary(val users: Int, val succeeded: Int, val failed: Int)

/** Splits "Ada Lovelace" into ("Ada", "Lovelace"); a single word is used for both. */
fun splitDisplayName(displayName: String): Pair<String, String> {
    val parts = displayName.trim().split(Regex("\\s+"), limit = 2)
    return if (parts.size == 2) parts[0] to parts[1] else parts[0] to parts[0]
}

/**
 * Keeps every SCIM-connected app in step with a platform user: create when the
 * user is new, suspend when they are suspended, reactivate, and delete when
 * they are deleted. Reconciliation is state-based ("make the app match this
 * user's status") rather than event-based, so it is idempotent: running it
 * again, for example from "Retry", is always safe.
 *
 * Failures never undo or block the platform-side change (the platform's own
 * account is the source of truth, AP-3); they are recorded per user and app
 * (provisioned_accounts.last_error), audited, and returned to the caller so
 * the admin sees them immediately and can retry.
 *
 * Only accounts this service created (or adopted after a "already exists"
 * answer) are ever touched, so a pre-existing app account is never suspended
 * or deleted by accident.
 */
@Service
class ProvisioningService(
    private val connections: ScimConnectionRepository,
    private val accounts: ProvisionedAccountRepository,
    private val scim: ScimClient,
    private val openBaoClient: OpenBaoClient,
    private val oidcClients: OidcClientRepository,
    private val samlSps: SamlSpRepository,
    private val identityClient: IdentityClient,
    private val auditPublisher: AuditPublisher,
) {
    /** Brings every enabled connection in line with the user's current status. */
    fun reconcile(user: ProvisionUser): List<TargetResult> =
        connections.findByTenantIdAndEnabledTrue(user.tenantId).map { reconcileOne(it, user) }

    fun reconcileOne(connection: ScimConnectionEntity, user: ProvisionUser): TargetResult {
        val appName = appName(connection)
        val token = tokenFor(connection)
        if (token.isNullOrBlank()) {
            val message = "No access token is stored for this connection. Save the connection again with a token."
            return failed(connection, user, appName, message)
        }
        val account = accounts.findByUserIdAndConnectionId(user.id, connection.id)

        return try {
            val action = when {
                account?.externalId == null -> createOrLink(connection, token, user)
                account.state == AccountState.ACTIVE.name && !user.active -> {
                    scim.setActive(connection.baseUrl, token, account.externalId!!, false)
                    saveAccount(connection, user, account.externalId, AccountState.SUSPENDED)
                    "suspended"
                }
                account.state == AccountState.SUSPENDED.name && user.active -> {
                    scim.setActive(connection.baseUrl, token, account.externalId!!, true)
                    saveAccount(connection, user, account.externalId, AccountState.ACTIVE)
                    "reactivated"
                }
                else -> {
                    // Nothing to change, but a leftover error from an earlier failed attempt is now moot.
                    if (account.lastError != null) saveAccount(connection, user, account.externalId, AccountState.valueOf(account.state))
                    "unchanged"
                }
            }
            if (action != "unchanged" && action != "skipped") audit("provisioning.user_$action", user, appName, null)
            TargetResult(appName, action, ok = true)
        } catch (ex: ScimException) {
            failed(connection, user, appName, ex.message ?: "The app returned an error.")
        }
    }

    /** A new user is created in the app; a user the app already has (409) is linked and made active. */
    private fun createOrLink(connection: ScimConnectionEntity, token: String, user: ProvisionUser): String {
        // A suspended user that was never created in the app has nothing to suspend there.
        if (!user.active) return "skipped"

        val (given, family) = splitDisplayName(user.displayName)
        val spec = ScimUserSpec(user.email, user.id.toString(), user.displayName, given, family, active = true)
        return try {
            val id = scim.createUser(connection.baseUrl, token, spec)
            saveAccount(connection, user, id, AccountState.ACTIVE)
            "created"
        } catch (ex: ScimException) {
            if (!ex.conflict) throw ex
            val existing = scim.findIdByUserName(connection.baseUrl, token, user.email) ?: throw ex
            scim.setActive(connection.baseUrl, token, existing, true)
            saveAccount(connection, user, existing, AccountState.ACTIVE)
            "linked"
        }
    }

    /** Deletes the app-side account for a deleted platform user. Only accounts we own are touched. */
    fun deprovision(tenantId: UUID, userId: UUID, email: String?): List<TargetResult> =
        accounts.findByUserId(userId).mapNotNull { account ->
            val connection = connections.findById(account.connectionId).orElse(null) ?: return@mapNotNull null
            val appName = appName(connection)
            val user = ProvisionUser(userId, tenantId, email ?: "", "", active = false)
            val externalId = account.externalId
            if (externalId == null) {
                accounts.delete(account)
                return@mapNotNull TargetResult(appName, "skipped", ok = true)
            }
            val token = tokenFor(connection)
            if (token.isNullOrBlank()) {
                return@mapNotNull failed(connection, user, appName, "No access token is stored for this connection.")
            }
            try {
                scim.deleteUser(connection.baseUrl, token, externalId)
                accounts.delete(account)
                audit("provisioning.user_deleted", user, appName, null)
                TargetResult(appName, "deleted", ok = true)
            } catch (ex: ScimException) {
                failed(connection, user, appName, ex.message ?: "The app returned an error.")
            }
        }

    /** Brings one connection in line for every user in the tenant (used after connecting an app). */
    fun syncConnection(connection: ScimConnectionEntity): SyncSummary {
        val users = identityClient.listUsers(connection.tenantId)
        var ok = 0
        var failedCount = 0
        for (u in users) {
            val result = reconcileOne(
                connection,
                ProvisionUser(u.id, u.tenantId, u.email, u.displayName, active = u.status == RemoteUserStatus.ACTIVE),
            )
            if (result.ok) ok++ else failedCount++
        }
        return SyncSummary(users.size, ok, failedCount)
    }

    private fun failed(connection: ScimConnectionEntity, user: ProvisionUser, appName: String, message: String): TargetResult {
        val account = accounts.findByUserIdAndConnectionId(user.id, connection.id)
        if (account != null || user.active) {
            val target = account ?: ProvisionedAccountEntity(UUID.randomUUID(), user.tenantId, user.id, connection.id)
            target.lastError = message.take(500)
            target.updatedAt = Instant.now()
            accounts.save(target)
        }
        audit("provisioning.failed", user, appName, message, failure = true)
        return TargetResult(appName, "failed", ok = false, error = message)
    }

    private fun saveAccount(connection: ScimConnectionEntity, user: ProvisionUser, externalId: String?, state: AccountState) {
        val account = accounts.findByUserIdAndConnectionId(user.id, connection.id)
            ?: ProvisionedAccountEntity(UUID.randomUUID(), user.tenantId, user.id, connection.id)
        account.externalId = externalId ?: account.externalId
        account.state = state.name
        account.lastError = null
        account.updatedAt = Instant.now()
        accounts.save(account)
    }

    fun appName(connection: ScimConnectionEntity): String =
        when (connection.appKind) {
            "OIDC" -> oidcClients.findById(connection.appId).map { it.name }.orElse(null)
            else -> samlSps.findById(connection.appId).map { it.name }.orElse(null)
        } ?: "(deleted app)"

    fun tokenFor(connection: ScimConnectionEntity): String? =
        openBaoClient.readSecretOrNull("scim/${connection.id}")?.get("token") as? String

    private fun audit(action: String, user: ProvisionUser, appName: String, error: String?, failure: Boolean = false) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = user.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-tenant-svc",
                action = action,
                result = if (failure) AuditResult.FAILURE else AuditResult.SUCCESS,
                reason = "app=$appName; user=${user.id}" + (error?.let { "; $it" } ?: ""),
            ),
        )
    }
}
