package com.iamplatform.session

import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Size
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
    // Sign-in context, captured server-side by iam-auth-svc. Added after the first release, so they
    // are optional: sessions already stored in Valkey simply have none.
    val userAgent: String? = null,
    val country: String? = null,
    val region: String? = null,
    val city: String? = null,
)

data class IssueSessionRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotNull
    val userId: UUID,

    val sourceIp: String? = null,
    val deviceId: String? = null,
    @field:Size(max = 512)
    val userAgent: String? = null,
    @field:Size(max = 8)
    val country: String? = null,
    @field:Size(max = 128)
    val region: String? = null,
    @field:Size(max = 128)
    val city: String? = null,
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
