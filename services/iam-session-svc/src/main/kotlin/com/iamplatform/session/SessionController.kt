package com.iamplatform.session

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/api/v1/sessions")
class SessionController(
    private val sessionService: SessionService,
) {

    @PostMapping
    fun issue(
        @Valid @RequestBody request: IssueSessionRequest,
        @RequestHeader("Idempotency-Key", required = false) idempotencyKey: String?,
    ): ResponseEntity<IssuedSessionResponse> {
        val result = sessionService.issue(request, idempotencyKey)
        val response = ResponseEntity.status(HttpStatus.CREATED)
        if (result.replayed) response.header("Idempotent-Replayed", "true")
        return response.body(result.toResponse())
    }

    // The token travels only in a header, never in the URL -- a path
    // parameter risks the raw token being recorded as a trace span
    // attribute by HTTP server instrumentation (docs/DECISIONS.md, Service
    // 6 entry, OQ-2).
    @GetMapping
    fun validate(@RequestHeader("X-Session-Token") token: String): ResponseEntity<SessionRecord> =
        ResponseEntity.ok(sessionService.find(token) ?: throw SessionNotFoundException())

    @DeleteMapping
    fun terminate(
        @RequestHeader("X-Session-Token") token: String,
        @RequestParam(required = false) reason: String?,
    ): ResponseEntity<Void> {
        sessionService.terminate(token, reason)
        return ResponseEntity.noContent().build()
    }
}
