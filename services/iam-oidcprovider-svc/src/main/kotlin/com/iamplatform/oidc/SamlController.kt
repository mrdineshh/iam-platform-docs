package com.iamplatform.oidc

import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.net.URI

data class SamlCompleteRequest(val sessionToken: String, val samlRequestId: String)
data class SamlCompleteResponse(val acsUrl: String, val samlResponse: String, val relayState: String?)
data class SamlIdpInfoResponse(val entityId: String, val ssoUrl: String, val certificatePem: String)

@RestController
class SamlController(
    private val samlService: SamlService,
    private val properties: OidcProperties,
) {

    // SP-initiated SSO (SAML 2.0 Bindings 3.4, HTTP-Redirect binding):
    // Google (or any registered SP) redirects the browser here with a
    // deflated+base64 AuthnRequest. Redirects on to iam-login-portal's own
    // SAML-aware page, exactly as GET /authorize does for OIDC -- never
    // authenticates anyone itself (AP-1).
    @GetMapping("/saml/sso")
    fun sso(
        @RequestParam("SAMLRequest") samlRequest: String,
        @RequestParam("RelayState", required = false) relayState: String?,
    ): ResponseEntity<Void> {
        val redirect = samlService.buildLoginRedirect(samlRequest, relayState, properties.loginPortalBaseUrl)
        return ResponseEntity.status(HttpStatus.FOUND).location(URI(redirect)).build()
    }

    // Called server-side by iam-login-portal after it has already
    // authenticated the user directly against iam-auth-svc -- never called
    // by a browser directly. Returns what the portal needs to render the
    // HTTP-POST binding's auto-submitting form to acsUrl.
    @PostMapping("/saml/complete")
    fun complete(@RequestBody request: SamlCompleteRequest): ResponseEntity<SamlCompleteResponse> {
        val completion = samlService.completeSamlAuthorization(request.sessionToken, request.samlRequestId)
        return ResponseEntity.ok(SamlCompleteResponse(completion.acsUrl, completion.samlResponseBase64, completion.relayState))
    }

    @GetMapping("/saml/metadata", produces = [MediaType.APPLICATION_XML_VALUE])
    fun metadata(): ResponseEntity<String> = ResponseEntity.ok(samlService.metadataXml())

    // Display-only JSON for iam-tenant-svc's browser-facing proxy
    // (admin-console can't reach this service directly -- no CORS here).
    @GetMapping("/saml/idp-info")
    fun idpInfo(): ResponseEntity<SamlIdpInfoResponse> {
        val (entityId, ssoUrl, certPem) = samlService.idpInfo()
        return ResponseEntity.ok(SamlIdpInfoResponse(entityId, ssoUrl, certPem))
    }
}
