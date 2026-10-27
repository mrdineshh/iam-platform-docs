package com.iamplatform.identity

import com.iamplatform.servicekit.error.ErrorResponse
import io.github.resilience4j.circuitbreaker.CallNotPermittedException
import jakarta.servlet.http.HttpServletRequest
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice
import org.springframework.web.client.ResourceAccessException

@RestControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(UserNotFoundException::class, TenantNotFoundException::class, GroupNotFoundException::class)
    fun handleNotFound(ex: RuntimeException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.NOT_FOUND).body(
            ErrorResponse.of(HttpStatus.NOT_FOUND.value(), "Not Found", ex.message ?: "", request.requestURI),
        )

    @ExceptionHandler(WeakPasswordException::class)
    fun handleWeakPassword(ex: WeakPasswordException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
            ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", ex.message ?: "", request.requestURI, "WEAK_PASSWORD"),
        )

    @ExceptionHandler(EmailAlreadyExistsException::class)
    fun handleConflict(ex: EmailAlreadyExistsException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
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

    @ExceptionHandler(CallNotPermittedException::class, ResourceAccessException::class)
    fun handleDownstreamUnavailable(ex: Exception, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(
            ErrorResponse.of(
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                "Service Unavailable",
                "iam-tenant-svc is currently unavailable",
                request.requestURI,
            ),
        )
}
