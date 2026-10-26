package com.iamplatform.oidc

import com.nimbusds.jose.jwk.JWKSet
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

@RestController
class DiscoveryController(
    private val tokenService: TokenService,
    private val properties: OidcProperties,
) {

    @GetMapping("/.well-known/openid-configuration")
    fun discovery(): Map<String, Any> {
        val issuer = properties.issuer
        return mapOf(
            "issuer" to issuer,
            "authorization_endpoint" to "$issuer/authorize",
            "token_endpoint" to "$issuer/token",
            "userinfo_endpoint" to "$issuer/userinfo",
            "jwks_uri" to "$issuer/jwks.json",
            "response_types_supported" to listOf("code"),
            "subject_types_supported" to listOf("public"),
            "id_token_signing_alg_values_supported" to listOf("RS256"),
            "scopes_supported" to listOf("openid", "profile", "email"),
            "token_endpoint_auth_methods_supported" to listOf("client_secret_post"),
        )
    }

    @GetMapping("/jwks.json")
    fun jwks(): Any = tokenService.publicJwkSet().toJSONObject()
}
