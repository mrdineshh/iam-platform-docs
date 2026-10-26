package com.iamplatform.auth

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

    @ExceptionHandler(InvalidCredentialsException::class)
    fun handleInvalidCredentials(ex: InvalidCredentialsException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.UNAUTHORIZED, ex.message ?: "", request)

    @ExceptionHandler(LoginDeniedException::class)
    fun handleDenied(ex: LoginDeniedException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.FORBIDDEN).body(
            ErrorResponse.of(HttpStatus.FORBIDDEN.value(), HttpStatus.FORBIDDEN.reasonPhrase, ex.message ?: "", request.requestURI, ex.errorCode.name),
        )

    @ExceptionHandler(LogoutSessionNotFoundException::class)
    fun handleLogoutNotFound(ex: LogoutSessionNotFoundException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.NOT_FOUND, ex.message ?: "", request)

    @ExceptionHandler(BreakGlassTokenInvalidException::class)
    fun handleBreakGlassInvalid(ex: BreakGlassTokenInvalidException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.FORBIDDEN, ex.message ?: "", request)

    @ExceptionHandler(BreakGlassUserNotFoundException::class)
    fun handleBreakGlassUserNotFound(ex: BreakGlassUserNotFoundException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.NOT_FOUND, ex.message ?: "", request)

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(ex: MethodArgumentNotValidException, request: HttpServletRequest): ResponseEntity<ErrorResponse> {
        val message = ex.bindingResult.fieldErrors.joinToString("; ") { "${it.field}: ${it.defaultMessage}" }
        return error(HttpStatus.BAD_REQUEST, message, request)
    }

    @ExceptionHandler(HttpMessageNotReadableException::class)
    fun handleUnreadable(ex: HttpMessageNotReadableException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.BAD_REQUEST, "Malformed or incomplete request body", request)

    @ExceptionHandler(MissingRequestHeaderException::class)
    fun handleMissingHeader(ex: MissingRequestHeaderException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.BAD_REQUEST, ex.message ?: "Missing required header", request)

    // identity-svc or session-svc unreachable -- the two calls AuthService
    // deliberately does NOT catch, so a genuine infra failure surfaces as a
    // clean 503 (BUILD_PLAN.md Service 7 TEST GATE), not a hang or a 500.
    @ExceptionHandler(CallNotPermittedException::class, ResourceAccessException::class)
    fun handleDownstreamUnavailable(ex: Exception, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.SERVICE_UNAVAILABLE, "A required downstream service is currently unavailable", request)

    private fun error(status: HttpStatus, message: String, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(status).body(ErrorResponse.of(status.value(), status.reasonPhrase, message, request.requestURI))
}
