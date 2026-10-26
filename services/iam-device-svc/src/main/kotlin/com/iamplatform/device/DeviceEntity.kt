package com.iamplatform.device

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

enum class DeviceStatus { PENDING, ACTIVE }

@Entity
@Table(name = "devices")
class DeviceEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "tenant_id", nullable = false)
    var tenantId: UUID,

    @Column(name = "user_id", nullable = false)
    var userId: UUID,

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 16)
    var status: DeviceStatus = DeviceStatus.PENDING,

    @Column(name = "totp_secret_ciphertext", nullable = false)
    var totpSecretCiphertext: ByteArray,

    @Column(name = "totp_secret_nonce", nullable = false)
    var totpSecretNonce: ByteArray,

    @Column(name = "fcm_token")
    var fcmToken: String? = null,

    @Column(name = "failed_totp_attempts", nullable = false)
    var failedTotpAttempts: Int = 0,

    @Column(name = "locked_until")
    var lockedUntil: Instant? = null,

    @Column(name = "created_at", nullable = false)
    var createdAt: Instant = Instant.now(),

    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),
)
