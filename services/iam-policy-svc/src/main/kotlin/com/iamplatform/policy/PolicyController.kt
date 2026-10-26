package com.iamplatform.policy

import jakarta.validation.Valid
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/api/v1")
class PolicyController(
    private val policyService: PolicyService,
    private val adminAccessGuard: AdminAccessGuard,
) {

    // Retrofitted for Service 14 (iam-admin-console) -- previously
    // unauthenticated, confirmed with product owner before changing (see
    // docs/DECISIONS.md and docs/specs/iam-admin-console-SPEC.md Section
    // 1.4). X-Session-Token now required; the tenantId inside the request
    // body is what's checked against the session, not a separate param.
    @PutMapping("/policies")
    fun putPolicy(
        @Valid @RequestBody request: PutPolicyRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<PolicyResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, request.tenantId)
        return ResponseEntity.ok(policyService.putPolicy(request).toResponse())
    }

    // Added for Service 14 (iam-admin-console).
    @GetMapping("/policies")
    fun getPolicy(
        @RequestParam tenantId: UUID,
        @RequestParam scope: PolicyScope,
        @RequestParam(required = false) scopeId: UUID?,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<PolicyResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(policyService.getPolicy(tenantId, scope, scopeId).toResponse())
    }

    // Not audited per-call (see docs/DECISIONS.md, Service 5 entry) -- this
    // sits on the hot path of every login/enforcement check, and the calling
    // service (iam-auth-svc, iam-enforcement-svc) is what records the
    // resulting security-relevant outcome (e.g. auth.login_denied). Not
    // admin-gated -- this is a service-to-service call, not an admin action.
    @PostMapping("/evaluate")
    fun evaluate(@Valid @RequestBody request: EvaluateRequest): ResponseEntity<EvaluateResponse> {
        val result = policyService.evaluate(request)
        return ResponseEntity.ok(
            EvaluateResponse(
                result.allowed, result.reason, result.policyScopeApplied,
                result.mfaRequired, result.totpReenrollEveryLogin,
            ),
        )
    }
}
