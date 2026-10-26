package com.iamplatform.enforcement

import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1")
class EnforcementController(
    private val enforcementService: EnforcementService,
) {

    @PostMapping("/enforce")
    fun enforce(
        @RequestHeader("X-Session-Token") token: String,
        @Valid @RequestBody request: EnforceRequest,
    ): ResponseEntity<EnforceResponse> =
        ResponseEntity.ok(enforcementService.enforce(token, request))
}
