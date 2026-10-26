package com.iamplatform.oidc

import com.iamplatform.servicekit.error.ErrorResponse
import io.github.resilience4j.circuitbreaker.CallNotPermittedException
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.client.ResourceAccessException

data class OAuthError(val error: String, val error_description: String? = null)

@RestControllerAdvice
class GlobalExceptionHandler {

    // GET /authorize's own error case: never redirect an invalid/unregistered
    // request anywhere -- render a direct error page instead (OAuth security
    // best practice, and BUILD_PLAN.md's own framing of this service).
    @ExceptionHandler(InvalidAuthorizeRequestException::class)
    fun handleInvalidAuthorize(ex: InvalidAuthorizeRequestException): ResponseEntity<String> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .contentType(MediaType.TEXT_HTML)
            .body(LoginFormRenderer.renderError(ex.message ?: "invalid request"))

    // POST /authorize/complete's 400/401 cases -- service-to-service JSON,
    // never HTML (see docs/specs/iam-login-portal-SPEC.md Section 1.1).
    @ExceptionHandler(AuthorizeCompleteException::class)
    fun handleAuthorizeCompleteInvalid(ex: AuthorizeCompleteException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
            ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), HttpStatus.BAD_REQUEST.reasonPhrase, ex.message ?: "", request.requestURI),
        )

    @ExceptionHandler(SessionInvalidException::class)
    fun handleSessionInvalid(ex: SessionInvalidException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            ErrorResponse.of(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.reasonPhrase, ex.message ?: "", request.requestURI),
        )

    @ExceptionHandler(InvalidGrantException::class)
    fun handleInvalidGrant(ex: InvalidGrantException): ResponseEntity<OAuthError> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST).body(OAuthError("invalid_grant", ex.message))

    @ExceptionHandler(InvalidClientException::class)
    fun handleInvalidClient(ex: InvalidClientException): ResponseEntity<OAuthError> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST).body(OAuthError("invalid_client", ex.message))

    @ExceptionHandler(InvalidTokenException::class)
    fun handleInvalidToken(ex: InvalidTokenException): ResponseEntity<OAuthError> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(OAuthError("invalid_token", ex.message))

    // GET /saml/sso's own error case -- same "never redirect an invalid
    // request anywhere" reasoning as InvalidAuthorizeRequestException.
    @ExceptionHandler(InvalidSamlRequestException::class, UnknownSamlSpException::class)
    fun handleInvalidSamlRequest(ex: RuntimeException): ResponseEntity<String> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST)
            .contentType(MediaType.TEXT_HTML)
            .body(LoginFormRenderer.renderError(ex.message ?: "invalid request"))

    @ExceptionHandler(SamlRequestNotFoundException::class, SamlSessionInvalidException::class)
    fun handleSamlSessionInvalid(ex: RuntimeException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            ErrorResponse.of(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.reasonPhrase, ex.message ?: "", request.requestURI),
        )

    // iam-tenant-svc, iam-session-svc, or iam-identity-svc unreachable --
    // Guardrails Section 2, and docs/specs/iam-login-portal-SPEC.md Section
    // 1.1's 503 case for /authorize/complete. Not previously handled here
    // (found while wiring this endpoint -- logged in docs/DECISIONS.md).
    @ExceptionHandler(CallNotPermittedException::class, ResourceAccessException::class)
    fun handleDownstreamUnavailable(ex: Exception, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(
            ErrorResponse.of(
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                HttpStatus.SERVICE_UNAVAILABLE.reasonPhrase,
                "A required downstream service is currently unavailable",
                request.requestURI,
            ),
        )
}
