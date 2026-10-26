package com.iamplatform.enforcement

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

    @ExceptionHandler(EnforcementDeniedException::class)
    fun handleDenied(ex: EnforcementDeniedException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
            ErrorResponse.of(HttpStatus.UNAUTHORIZED.value(), "Unauthorized", ex.message ?: "", request.requestURI),
        )

    @ExceptionHandler(MissingRequestHeaderException::class)
    fun handleMissingHeader(ex: MissingRequestHeaderException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
            ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", ex.message ?: "", request.requestURI),
        )

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(ex: MethodArgumentNotValidException, request: HttpServletRequest): ResponseEntity<ErrorResponse> {
        val message = ex.bindingResult.fieldErrors.joinToString("; ") { "${it.field}: ${it.defaultMessage}" }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
            ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", message, request.requestURI),
        )
    }

    // See docs/DECISIONS.md, Service 6 entry -- Kotlin non-null request
    // fields make Jackson reject a missing field before bean validation runs.
    @ExceptionHandler(HttpMessageNotReadableException::class)
    fun handleUnreadable(ex: HttpMessageNotReadableException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
            ErrorResponse.of(HttpStatus.BAD_REQUEST.value(), "Bad Request", "Malformed or incomplete request body", request.requestURI),
        )

    @ExceptionHandler(CallNotPermittedException::class, ResourceAccessException::class)
    fun handleDownstreamUnavailable(ex: Exception, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(
            ErrorResponse.of(HttpStatus.SERVICE_UNAVAILABLE.value(), "Service Unavailable", "iam-session-svc is currently unavailable", request.requestURI),
        )
}
