package com.iamplatform.oidc

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RestController

data class UserInfoResponse(val sub: String, val email: String, val tenant_id: String)

@RestController
class UserInfoController(
    private val oidcService: OidcService,
) {

    @GetMapping("/userinfo")
    fun userInfo(@RequestHeader("Authorization") authorization: String): ResponseEntity<UserInfoResponse> {
        if (!authorization.startsWith("Bearer ")) {
            throw InvalidTokenException("Authorization header must be a Bearer token")
        }
        val accessToken = authorization.removePrefix("Bearer ").trim()
        val result = oidcService.userInfo(accessToken)
        return ResponseEntity.ok(UserInfoResponse(result.sub.toString(), result.email, result.tenantId.toString()))
    }
}
