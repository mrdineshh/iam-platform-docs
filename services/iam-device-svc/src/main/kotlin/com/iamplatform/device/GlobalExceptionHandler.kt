package com.iamplatform.device

import com.iamplatform.device.fcm.FcmSendFailedException
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

    @ExceptionHandler(UserNotFoundException::class, DeviceNotFoundException::class, NoPushCapableDeviceException::class, ChallengeNotFoundException::class)
    fun handleNotFound(ex: RuntimeException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.NOT_FOUND).body(
            ErrorResponse.of(HttpStatus.NOT_FOUND.value(), "Not Found", ex.message ?: "", request.requestURI),
        )

    @ExceptionHandler(ChallengeAlreadyResolvedException::class)
    fun handleConflict(ex: ChallengeAlreadyResolvedException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
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
            ErrorResponse.of(
                HttpStatus.SERVICE_UNAVAILABLE.value(),
                "Service Unavailable",
                "iam-identity-svc is currently unavailable",
                request.requestURI,
            ),
        )

    @ExceptionHandler(FcmSendFailedException::class)
    fun handleFcmFailure(ex: FcmSendFailedException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(
            ErrorResponse.of(HttpStatus.SERVICE_UNAVAILABLE.value(), "Service Unavailable", "Push notification delivery failed", request.requestURI),
        )
}
