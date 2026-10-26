package com.iamplatform.oidc

import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration

@ConfigurationProperties(prefix = "iam.oidc")
data class OidcProperties(
    // MVP-TEMPORARY: a single platform-wide issuer URL, not per-tenant
    // subdomain-based (BRD FR-6.2) -- there's no real ingress/DNS wiring in
    // local docker-compose to make tenant.platform.com resolve anywhere.
    // Must be the externally-reachable URL a third-party app's browser
    // redirect and server-to-server /token call can both actually hit --
    // for local testing that's the host-mapped port, not the internal
    // Docker service name.
    val issuer: String = "http://localhost:8090",
    val accessTokenTtl: Duration = Duration.ofMinutes(10),
    val idTokenTtl: Duration = Duration.ofMinutes(10),
    // Added for Service 13 (iam-login-portal) -- see docs/DECISIONS.md,
    // Service 13 pre-implementation entry, and
    // docs/specs/iam-login-portal-SPEC.md Section 0/3. GET /authorize
    // redirects here instead of rendering its own form. If this contains the
    // literal token "{subdomain}", it's substituted into the URL as a real
    // subdomain host (production, FR-6.2). Otherwise (local Docker Compose,
    // no wildcard DNS) the subdomain is appended as a `?tenant=` query
    // param instead -- same fallback pattern as iam-geo-svc's private-IP
    // fixture.
    val loginPortalBaseUrl: String = "http://localhost:3001",
)
