package com.iamplatform.tenant

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

/**
 * A SAML 2.0 Service Provider registration -- the SAML counterpart to
 * OidcClientEntity, kept as its own table/type rather than overloading
 * oidc_clients with a discriminator: the two protocols need different,
 * mostly-non-overlapping fields (an SP has no client secret; an OIDC
 * client has no ACS URL), and SAML has no equivalent to issuing a secret
 * at all -- this platform's own IdP signing cert (platform-wide, see
 * SamlSigningKeyProvider in iam-oidcprovider-svc) is what the SP verifies
 * assertions against, not a per-registration credential.
 */
@Entity
@Table(name = "saml_sps")
class SamlSpEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "tenant_id", nullable = false)
    var tenantId: UUID,

    @Column(name = "name", nullable = false)
    var name: String,

    // The SP's own identifier, e.g. "google.com" for Google Workspace's
    // third-party IdP SSO profile -- what an incoming AuthnRequest's
    // <Issuer> is matched against, and what this IdP's signed assertions
    // put in <AudienceRestriction>.
    @Column(name = "sp_entity_id", nullable = false)
    var spEntityId: String,

    // Where the signed SAML Response is POSTed -- the SP's Assertion
    // Consumer Service URL.
    @Column(name = "acs_url", nullable = false)
    var acsUrl: String,

    // Same purpose as OidcClientEntity.launchUrl -- optional, shows a tile
    // on the launchpad if set.
    @Column(name = "launch_url")
    var launchUrl: String? = null,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),
)
