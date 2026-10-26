package com.iamplatform.audit

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditResult
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "audit_events")
class AuditEventEntity(
    @Id
    @Column(name = "event_id")
    var eventId: UUID,

    @Column(name = "correlation_id", nullable = false)
    var correlationId: String,

    @Column(name = "occurred_at", nullable = false)
    var occurredAt: Instant,

    @Column(name = "tenant_id", nullable = false)
    var tenantId: UUID,

    @Enumerated(EnumType.STRING)
    @Column(name = "actor_type", nullable = false, length = 16)
    var actorType: ActorType,

    @Column(name = "actor_id", nullable = false)
    var actorId: String,

    @Column(name = "action", nullable = false)
    var action: String,

    @Enumerated(EnumType.STRING)
    @Column(name = "result", nullable = false, length = 16)
    var result: AuditResult,

    @Column(name = "reason")
    var reason: String? = null,

    @Column(name = "source_ip")
    var sourceIp: String? = null,

    @Column(name = "geo")
    var geo: String? = null,

    @Column(name = "device_id")
    var deviceId: String? = null,

    @Column(name = "policy_scope_applied")
    var policyScopeApplied: String? = null,

    @Column(name = "received_at", nullable = false)
    var receivedAt: Instant = Instant.now(),
)
