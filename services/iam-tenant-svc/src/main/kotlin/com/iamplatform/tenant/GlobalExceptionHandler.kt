package com.iamplatform.tenant

import com.iamplatform.servicekit.error.ErrorResponse
import io.github.resilience4j.circuitbreaker.CallNotPermittedException
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.MissingRequestHeaderException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.client.ResourceAccessException

@RestControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(
        TenantNotFoundException::class, TenantSubdomainNotFoundException::class,
        OidcClientNotFoundException::class, SamlSpNotFoundException::class,
    )
    fun handleNotFound(ex: RuntimeException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.NOT_FOUND).body(
            ErrorResponse.of(HttpStatus.NOT_FOUND.value(), "Not Found", ex.message ?: "", request.requestURI),
        )

    @ExceptionHandler(SubdomainAlreadyExistsException::class, SamlSpEntityIdAlreadyExistsException::class)
    fun handleConflict(ex: RuntimeException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.CONFLICT).body(
            ErrorResponse.of(HttpStatus.CONFLICT.value(), "Conflict", ex.message ?: "", request.requestURI),
        )

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(ex: MethodArgumentNotValidException, request: HttpServletRequest): ResponseEntity<ErrorResponse> {
        val message = ex.bindingResult.fieldErrors.joinToString("; ") { "${it.field}: ${it.defaultMessage}" }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
            ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", message, request.requestURI),
        )
    }

    // Kotlin non-null request fields make Jackson reject a missing field while
    // reading the body, before bean validation ever runs -- so this, not
    // MethodArgumentNotValidException, is what a missing required field raises.
    // Found in Service 6 (iam-session-svc), confirmed live here too; see
    // docs/DECISIONS.md, Service 6 entry.
    @ExceptionHandler(HttpMessageNotReadableException::class)
    fun handleUnreadable(ex: HttpMessageNotReadableException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
            ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", "Malformed or incomplete request body", request.requestURI),
        )

    // Added for Service 14 (iam-admin-console)'s admin-gated endpoints.
    @ExceptionHandler(MissingRequestHeaderException::class)
    fun handleMissingHeader(ex: MissingRequestHeaderException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
            ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", ex.message ?: "Missing required header", request.requestURI),
        )

    @ExceptionHandler(AdminSessionInvalidException::class)
    fun handleAdminSessionInvalid(ex: AdminSessionInvalidException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            ErrorResponse.of(HttpStatus.UNAUTHORIZED.value(), "Unauthorized", ex.message ?: "", request.requestURI),
        )

    @ExceptionHandler(AdminAccessDeniedException::class)
    fun handleAdminAccessDenied(ex: AdminAccessDeniedException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.FORBIDDEN).body(
            ErrorResponse.of(HttpStatus.FORBIDDEN.value(), "Forbidden", ex.message ?: "", request.requestURI),
        )

    // iam-session-svc or iam-identity-svc unreachable -- this service's
    // first outbound calls (Service 14), same pattern as every other
    // service's downstream-unavailable handler.
    @ExceptionHandler(CallNotPermittedException::class, ResourceAccessException::class)
    fun handleDownstreamUnavailable(ex: Exception, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(
            ErrorResponse.of(
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                "Service Unavailable",
                "A required downstream service is currently unavailable",
                request.requestURI,
            ),
        )
}
