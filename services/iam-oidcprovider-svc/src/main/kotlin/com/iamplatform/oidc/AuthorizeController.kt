package com.iamplatform.oidc

import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.net.URI
import java.util.UUID

data class AuthorizeCompleteRequest(
    val sessionToken: String,
    val clientId: UUID,
    val redirectUri: String,
    val scope: String,
    val state: String,
)

data class AuthorizeCompleteResponse(val redirectUri: String)

@RestController
class AuthorizeController(
    private val oidcService: OidcService,
) {

    // Redirects to iam-login-portal (Service 13) rather than rendering an
    // inline form -- see docs/DECISIONS.md, Service 13 pre-implementation
    // entry, and docs/specs/iam-login-portal-SPEC.md Section 0. Invalid
    // client_id/redirect_uri still never redirects anywhere -- that error
    // case is handled by GlobalExceptionHandler's HTML error page, unchanged.
    @GetMapping("/authorize")
    fun authorize(
        @RequestParam("response_type") responseType: String,
        @RequestParam("client_id") clientId: UUID,
        @RequestParam("redirect_uri") redirectUri: String,
        @RequestParam(required = false, defaultValue = "openid") scope: String,
        @RequestParam(required = false, defaultValue = "") state: String,
    ): ResponseEntity<Void> {
        val redirect = oidcService.buildLoginRedirect(clientId, redirectUri, scope, state)
        return ResponseEntity.status(HttpStatus.FOUND).location(URI(redirect)).build()
    }

    // Replaces the removed POST /authorize/login. Called server-side by
    // iam-login-portal after it has already authenticated the user directly
    // against iam-auth-svc -- never called by a browser directly, and never
    // renders HTML (JSON in, JSON out).
    @PostMapping("/authorize/complete")
    fun complete(@RequestBody request: AuthorizeCompleteRequest): ResponseEntity<AuthorizeCompleteResponse> {
        val redirect = oidcService.completeAuthorization(
            request.sessionToken, request.clientId, request.redirectUri, request.scope, request.state,
        )
        return ResponseEntity.ok(AuthorizeCompleteResponse(redirect))
    }
}
