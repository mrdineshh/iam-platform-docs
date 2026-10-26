package com.iamplatform.tenant

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

enum class TenantStatus { ACTIVE, SUSPENDED }

@Entity
@Table(name = "tenants")
class TenantEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "name", nullable = false)
    var name: String,

    @Column(name = "subdomain", nullable = false, unique = true)
    var subdomain: String,

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    var status: TenantStatus = TenantStatus.ACTIVE,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),
)
