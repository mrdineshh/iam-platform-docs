package com.iamplatform.enforcement

import jakarta.validation.constraints.NotBlank
import java.util.UUID

data class EnforceRequest(
    // MVP-TEMPORARY: client-supplied, not server-derived -- see
    // docs/DECISIONS.md, Service 7 entry, and contracts/iam-enforcement-svc.yaml.
    @field:NotBlank
    val sourceIp: String,
)

data class EnforceResponse(
    val allowed: Boolean,
    val sessionId: UUID,
    val tenantId: UUID,
    val userId: UUID,
    val country: String,
)

class EnforcementDeniedException(reason: String) : RuntimeException(reason)
