package com.iamplatform.session

import jakarta.validation.constraints.NotNull
import org.springframework.boot.context.properties.ConfigurationProperties
import java.time.Duration
import java.time.Instant
import java.util.UUID

@ConfigurationProperties(prefix = "iam.session")
data class SessionProperties(
    val ttl: Duration = Duration.ofHours(1),
    val idempotencyWindow: Duration = Duration.ofMinutes(10),
)

/** What's stored in Valkey. Never contains the token itself -- see [SessionTokens.hash]. */
data class SessionRecord(
    val sessionId: UUID,
    val tenantId: UUID,
    val userId: UUID,
    val sourceIp: String?,
    val deviceId: String?,
    val issuedAt: Instant,
    val expiresAt: Instant,
)

data class IssueSessionRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotNull
    val userId: UUID,

    val sourceIp: String? = null,
    val deviceId: String? = null,
)

data class IssueResult(
    val token: String,
    val session: SessionRecord,
    val replayed: Boolean,
)

data class IssuedSessionResponse(
    val token: String,
    val sessionId: UUID,
    val tenantId: UUID,
    val userId: UUID,
    val sourceIp: String?,
    val deviceId: String?,
    val issuedAt: Instant,
    val expiresAt: Instant,
)

fun IssueResult.toResponse(): IssuedSessionResponse =
    IssuedSessionResponse(
        token = token,
        sessionId = session.sessionId,
        tenantId = session.tenantId,
        userId = session.userId,
        sourceIp = session.sourceIp,
        deviceId = session.deviceId,
        issuedAt = session.issuedAt,
        expiresAt = session.expiresAt,
    )

data class TerminatedSessionsResponse(val terminated: Int)

class SessionNotFoundException : RuntimeException("Session not found, expired, or terminated")

class IdempotencyConflictException(message: String) : RuntimeException(message)
