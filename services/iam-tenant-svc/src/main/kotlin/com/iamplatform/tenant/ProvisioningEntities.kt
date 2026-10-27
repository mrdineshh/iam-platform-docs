package com.iamplatform.tenant

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import java.time.Instant
import java.util.UUID

/** A SCIM 2.0 endpoint an app exposes for user provisioning. The bearer token lives in OpenBao, never here. */
@Entity
@Table(name = "scim_connections")
class ScimConnectionEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "tenant_id", nullable = false)
    var tenantId: UUID,

    // "OIDC" or "SAML": which of the two connected-app tables app_id points into.
    @Column(name = "app_kind", nullable = false, length = 16)
    var appKind: String,

    @Column(name = "app_id", nullable = false)
    var appId: UUID,

    @Column(name = "base_url", nullable = false, length = 1024)
    var baseUrl: String,

    @Column(name = "enabled", nullable = false)
    var enabled: Boolean = true,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),

    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),
)

enum class AccountState { PENDING, ACTIVE, SUSPENDED }

/** The app-side account created (or adopted) for a platform user. Only rows here are ever modified or deleted. */
@Entity
@Table(name = "provisioned_accounts")
class ProvisionedAccountEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "tenant_id", nullable = false)
    var tenantId: UUID,

    @Column(name = "user_id", nullable = false)
    var userId: UUID,

    @Column(name = "connection_id", nullable = false)
    var connectionId: UUID,

    @Column(name = "external_id", length = 255)
    var externalId: String? = null,

    @Column(name = "state", nullable = false, length = 16)
    var state: String = AccountState.PENDING.name,

    @Column(name = "last_error")
    var lastError: String? = null,

    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),
)

interface ScimConnectionRepository : JpaRepository<ScimConnectionEntity, UUID> {
    fun findByTenantId(tenantId: UUID): List<ScimConnectionEntity>

    fun findByTenantIdAndEnabledTrue(tenantId: UUID): List<ScimConnectionEntity>

    fun findByTenantIdAndAppKindAndAppId(tenantId: UUID, appKind: String, appId: UUID): ScimConnectionEntity?
}

interface ProvisionedAccountRepository : JpaRepository<ProvisionedAccountEntity, UUID> {
    fun findByUserId(userId: UUID): List<ProvisionedAccountEntity>

    fun findByUserIdAndConnectionId(userId: UUID, connectionId: UUID): ProvisionedAccountEntity?

    fun findByConnectionId(connectionId: UUID): List<ProvisionedAccountEntity>
}
