package com.iamplatform.oidc

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController

data class TerminateAccessTokenRequest(val accessToken: String, val reason: String)
data class TerminateAccessTokenResponse(val terminated: Boolean)

/**
 * Not part of the public OIDC contract -- only iam-enforcement-svc's gateway
 * cookie-login path calls this, to kill the underlying platform session when
 * its own continuous enforcement check denies a request made with the
 * gateway's cookie instead of a raw X-Session-Token (see docs/DECISIONS.md,
 * gateway cookie-login entry). Deliberately never hands the raw session
 * token back to any caller -- see OidcService.terminateByAccessToken.
 */
@RestController
class InternalController(
    private val oidcService: OidcService,
) {
    @PostMapping("/internal/access-tokens/terminate")
    fun terminate(@RequestBody request: TerminateAccessTokenRequest): ResponseEntity<TerminateAccessTokenResponse> {
        val terminated = oidcService.terminateByAccessToken(request.accessToken, request.reason)
        return ResponseEntity.ok(TerminateAccessTokenResponse(terminated))
    }
}
