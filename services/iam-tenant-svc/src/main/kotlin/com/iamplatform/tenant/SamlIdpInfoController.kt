package com.iamplatform.tenant

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RestController

/** Display-only proxy for admin-console's SAML setup Integration tab -- see OidcProviderClient. */
@RestController
class SamlIdpInfoController(
    private val oidcProviderClient: OidcProviderClient,
    private val adminAccessGuard: AdminAccessGuard,
) {
    @GetMapping("/api/v1/saml-idp-info")
    fun samlIdpInfo(@RequestHeader("X-Session-Token") sessionToken: String): ResponseEntity<RemoteSamlIdpInfo> {
        adminAccessGuard.requireValidSession(sessionToken)
        return ResponseEntity.ok(oidcProviderClient.samlIdpInfo())
    }
}
