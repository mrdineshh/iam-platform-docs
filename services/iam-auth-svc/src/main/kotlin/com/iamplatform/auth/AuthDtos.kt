package com.iamplatform.auth

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Pattern
import java.time.Instant
import java.util.UUID

data class LoginRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    val email: String,

    @field:NotBlank
    val password: String,

    // Only a fallback for trusted internal callers (iam-login-portal derives it server-side). Requests
    // that arrive through the public reverse proxy carry X-Forwarded-For, which always wins -- see
    // ClientContext. Optional so clients no longer need to supply (or be trusted for) their own IP.
    val sourceIp: String = "",

    // Added for Service 9 (docs/DECISIONS.md, confirmed with product owner).
    // Present -> TOTP path; absent -> blocking push path. See
    // contracts/iam-auth-svc.yaml for why there's no separate MFA endpoint.
    @field:Pattern(regexp = "^\\d{6}$")
    val totpCode: String? = null,

    // The browser's User-Agent, forwarded by iam-login-portal (whose own request to this service
    // carries the portal's User-Agent, not the person's). Direct browser callers need not send it.
    val userAgent: String? = null,
)

data class LoginResponse(
    // Nullable -- absent exactly when enrollmentRequired is true (first
    // login, no active 2FA device yet: see AuthService.login). Exactly one
    // of {token set, enrollmentRequired=true} holds for any response.
    val token: String? = null,
    val sessionId: UUID? = null,
    val expiresAt: Instant? = null,
    // Added for Service 14 (iam-admin-console) -- see docs/DECISIONS.md.
    // UI-branching convenience only; every admin-gated backend endpoint
    // independently re-verifies role itself, never trusts this alone.
    val role: String? = null,

    // Self-service first-login 2FA enrollment (see iam-device-svc's
    // ensure-pending). When true, no session was issued -- the caller
    // (iam-login-portal) shows this QR, the user scans + enters the code,
    // and resubmits the exact same /login call with totpCode now filled in
    // to actually complete login and activate the device.
    val enrollmentRequired: Boolean = false,
    val totpSecret: String? = null,
    val provisioningUri: String? = null,
)

// Added for iam-login-portal's multi-step wizard -- see AuthService.precheck.
// Same shape as LoginRequest minus totpCode (a precheck call never carries one).
data class PrecheckRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    val email: String,

    @field:NotBlank
    val password: String,

    val sourceIp: String = "",

    val userAgent: String? = null,
)

data class PrecheckResponse(
    val mfaRequired: Boolean,
    val enrollmentRequired: Boolean,
    val totpSecret: String? = null,
    val provisioningUri: String? = null,
)

class InvalidCredentialsException : RuntimeException("Invalid credentials")

// Added for Service 13 (iam-login-portal) -- see docs/DECISIONS.md, Service 13
// pre-implementation entry, and contracts/iam-auth-svc.yaml. Lets a caller
// branch on the denial cause without parsing the free-text reason string.
enum class AuthErrorCode {
    ACCOUNT_SUSPENDED,
    ACCOUNT_LOCKED,
    LOCATION_UNVERIFIED,
    POLICY_UNAVAILABLE,
    POLICY_DENIED,
    NO_SECOND_FACTOR_ENROLLED,
    NO_PUSH_DEVICE_ENROLLED,
    SECOND_FACTOR_UNAVAILABLE,
    TOTP_INVALID,
    TOTP_LOCKED,
    PUSH_DENIED,
    PUSH_TIMEOUT,
}

class LoginDeniedException(reason: String, val errorCode: AuthErrorCode) : RuntimeException(reason)

class LogoutSessionNotFoundException : RuntimeException("Session not found, expired, or terminated")
