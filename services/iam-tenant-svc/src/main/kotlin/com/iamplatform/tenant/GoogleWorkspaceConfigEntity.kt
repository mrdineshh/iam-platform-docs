package com.iamplatform.tenant

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

/**
 * Enables auto-provisioning: creating a user in this platform also creates
 * the matching Google Workspace account (Admin SDK Directory API), so an
 * admin never has to do that second step by hand. The service account's
 * private key lives in OpenBao under "google-workspace/<tenantId>", not
 * here -- this row only records what's needed to know the integration is
 * configured and where new users should land.
 */
@Entity
@Table(name = "google_workspace_configs")
class GoogleWorkspaceConfigEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "tenant_id", nullable = false, unique = true)
    var tenantId: UUID,

    // The Workspace domain, e.g. "demo.econz.net".
    @Column(name = "domain", nullable = false)
    var domain: String,

    // A real super admin's email -- the service account impersonates this
    // identity for every Directory API call (domain-wide delegation
    // requires impersonating a real user, it can't act as itself).
    @Column(name = "admin_email", nullable = false)
    var adminEmail: String,

    // e.g. "/Ratnesh Test" -- new users land here directly instead of the
    // root OU, so they're already covered by whatever SSO profile
    // assignment exists for that OU (see docs/INTERNALS.md SAML section).
    // Null = Google's default root OU.
    @Column(name = "org_unit_path")
    var orgUnitPath: String? = null,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),
)
