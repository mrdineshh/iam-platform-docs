package com.iamplatform.tenant

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.util.UUID

/**
 * Which groups (iam-identity-svc's groups.id -- same cross-service
 * by-convention reference iam-policy-svc's policies.scope_id already uses
 * for OU scope, no DB-level FK across services) may see and launch a given
 * OIDC client on "My Apps". Own table rather than a column on
 * OidcClientEntity because this is many-to-many: one app can be shared by
 * several groups.
 */
@Entity
@Table(name = "oidc_client_groups")
class OidcClientGroupEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "oidc_client_id", nullable = false)
    var oidcClientId: UUID,

    @Column(name = "group_id", nullable = false)
    var groupId: UUID,
)

/** SAML counterpart to [OidcClientGroupEntity], same reasoning. */
@Entity
@Table(name = "saml_sp_groups")
class SamlSpGroupEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "saml_sp_id", nullable = false)
    var samlSpId: UUID,

    @Column(name = "group_id", nullable = false)
    var groupId: UUID,
)
