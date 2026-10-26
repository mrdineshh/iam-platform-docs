package com.iamplatform.session

import com.iamplatform.servicekit.error.ErrorResponse
import jakarta.servlet.http.HttpServletRequest
import org.springframework.dao.DataAccessResourceFailureException
import org.springframework.dao.QueryTimeoutException
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.http.converter.HttpMessageNotReadableException
import org.springframework.web.bind.MethodArgumentNotValidException
import org.springframework.web.bind.MissingRequestHeaderException
import org.springframework.web.bind.annotation.ExceptionHandler
import org.springframework.web.bind.annotation.RestControllerAdvice

@RestControllerAdvice
class GlobalExceptionHandler {

    @ExceptionHandler(SessionNotFoundException::class)
    fun handleNotFound(ex: SessionNotFoundException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.NOT_FOUND, ex.message ?: "", request)

    @ExceptionHandler(IdempotencyConflictException::class)
    fun handleConflict(ex: IdempotencyConflictException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.CONFLICT, ex.message ?: "", request)

    @ExceptionHandler(MethodArgumentNotValidException::class)
    fun handleValidation(ex: MethodArgumentNotValidException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(
            HttpStatus.BAD_REQUEST,
            ex.bindingResult.fieldErrors.joinToString("; ") { "${it.field}: ${it.defaultMessage}" },
            request,
        )

    // Kotlin non-null request fields make Jackson reject a missing field while
    // reading the body, before bean validation ever runs -- so this, not
    // MethodArgumentNotValidException, is what a missing tenantId/userId raises.
    @ExceptionHandler(HttpMessageNotReadableException::class)
    fun handleUnreadable(ex: HttpMessageNotReadableException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.BAD_REQUEST, "Malformed or incomplete request body", request)

    @ExceptionHandler(MissingRequestHeaderException::class)
    fun handleMissingHeader(ex: MissingRequestHeaderException, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.BAD_REQUEST, ex.message ?: "Missing required header", request)

    @ExceptionHandler(DataAccessResourceFailureException::class, QueryTimeoutException::class)
    fun handleStoreUnavailable(ex: Exception, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        error(HttpStatus.SERVICE_UNAVAILABLE, "Session store is currently unavailable", request)

    private fun error(status: HttpStatus, message: String, request: HttpServletRequest): ResponseEntity<ErrorResponse> =
        ResponseEntity.status(status).body(ErrorResponse.of(status.value(), status.reasonPhrase, message, request.requestURI))
}
