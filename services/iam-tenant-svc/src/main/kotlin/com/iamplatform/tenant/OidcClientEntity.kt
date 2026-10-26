package com.iamplatform.tenant

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

/**
 * An OAuth2/OIDC client registration for a tenant's downstream app (e.g.
 * Grafana) to use `iam-oidcprovider-svc` (Service 11) as its login provider.
 * `id` doubles as the OIDC `client_id` -- there's no reason to mint a
 * second identifier for the same concept.
 */
@Entity
@Table(name = "oidc_clients")
class OidcClientEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "tenant_id", nullable = false)
    var tenantId: UUID,

    @Column(name = "name", nullable = false)
    var name: String,

    @Column(name = "client_secret_hash", nullable = false)
    var clientSecretHash: String,

    // Comma-joined, same pragmatic choice as iam-policy-svc's country lists
    // -- a handful of values, not worth a separate table or array column.
    @Column(name = "redirect_uris", nullable = false)
    var redirectUris: String,

    // Added for the admin-console app launchpad -- where a user's browser
    // should go to actually start using this app once they click its
    // tile. Nullable: clients registered before this existed (or apps
    // that don't want a launchpad tile at all) just don't show up there.
    // Deliberately NOT validated as one of the client's own redirectUris
    // -- for an SSO-aware app (see iam-login-portal's SSO cookie), the
    // right value is that app's own *login-start* URL (e.g.
    // https://app/api/v1/auth/oidc/start), which redirects into the OIDC
    // flow itself and is never a registered redirect_uri.
    @Column(name = "launch_url")
    var launchUrl: String? = null,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),
) {
    val redirectUriList: List<String>
        get() = redirectUris.split(",").map { it.trim() }.filter { it.isNotBlank() }
}

fun List<String>.toRedirectUrisCsv(): String = joinToString(",")
