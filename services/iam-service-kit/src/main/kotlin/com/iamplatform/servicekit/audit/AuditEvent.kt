package com.iamplatform.servicekit.audit

import java.time.Instant
import java.util.UUID

enum class ActorType { USER, ADMIN, SYSTEM, AGENT }
enum class AuditResult { SUCCESS, FAILURE, DENIED }

data class AuditEvent(
    val eventId: UUID = UUID.randomUUID(),
    val correlationId: String,
    val timestamp: Instant = Instant.now(),
    val tenantId: UUID,
    val actorType: ActorType,
    val actorId: String,
    val action: String,
    val result: AuditResult,
    val reason: String? = null,
    val sourceIp: String? = null,
    val geo: String? = null,
    val deviceId: String? = null,
    val policyScopeApplied: String? = null,
)

interface AuditPublisher {
    fun publish(event: AuditEvent)
}
