package com.iamplatform.oidc

import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

data class TokenResponse(
    val access_token: String,
    val id_token: String,
    val token_type: String = "Bearer",
    val expires_in: Long,
)

@RestController
class TokenController(
    private val oidcService: OidcService,
) {

    @PostMapping("/token", consumes = [MediaType.APPLICATION_FORM_URLENCODED_VALUE])
    fun token(
        @RequestParam("grant_type") grantType: String,
        @RequestParam code: String,
        @RequestParam("redirect_uri") redirectUri: String,
        @RequestParam("client_id") clientId: UUID,
        @RequestParam("client_secret") clientSecret: String,
    ): ResponseEntity<TokenResponse> {
        val issuance = oidcService.exchangeToken(grantType, code, redirectUri, clientId, clientSecret)
        return ResponseEntity.ok(TokenResponse(issuance.accessToken, issuance.idToken, expires_in = issuance.expiresIn))
    }
}
