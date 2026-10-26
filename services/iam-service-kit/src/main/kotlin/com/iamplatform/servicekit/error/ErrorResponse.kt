package com.iamplatform.servicekit.error

import com.iamplatform.servicekit.correlation.CorrelationId
import java.time.Instant

/**
 * The one error shape every service returns, so a caller never has to
 * special-case a per-service error format (Guardrails Section 2).
 */
data class ErrorResponse(
    val timestamp: Instant,
    val status: Int,
    val error: String,
    val message: String,
    val path: String,
    val correlationId: String,
    // Optional, additive (Service 13 / iam-login-portal interview -- see
    // docs/DECISIONS.md). Nullable, defaults to omitted so every existing
    // caller of `of(...)` across every service is unaffected. A stable,
    // machine-readable code a UI can branch on without parsing `message`.
    // Only iam-auth-svc populates it today.
    val errorCode: String? = null,
) {
    companion object {
        fun of(status: Int, error: String, message: String, path: String, errorCode: String? = null): ErrorResponse =
            ErrorResponse(
                timestamp = Instant.now(),
                status = status,
                error = error,
                message = message,
                path = path,
                correlationId = CorrelationId.get(),
                errorCode = errorCode,
            )
    }
}
