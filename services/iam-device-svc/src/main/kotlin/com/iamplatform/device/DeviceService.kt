package com.iamplatform.device

import com.iamplatform.device.client.IdentityClient
import com.iamplatform.device.crypto.Base32
import com.iamplatform.device.crypto.TotpCryptoService
import com.iamplatform.device.crypto.TotpGenerator
import com.iamplatform.device.fcm.FcmClient
import com.iamplatform.device.fcm.FcmSendFailedException
import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import java.net.URLEncoder
import java.security.SecureRandom
import java.time.Instant
import java.util.UUID

private fun DeviceStatus.toVerifyStatus(): DeviceStatus2 =
    if (this == DeviceStatus.ACTIVE) DeviceStatus2.ACTIVE else DeviceStatus2.PENDING

@Service
class DeviceService(
    private val repository: DeviceRepository,
    private val identityClient: IdentityClient,
    private val totpCrypto: TotpCryptoService,
    private val fcmClient: FcmClient,
    private val pushChallengeService: PushChallengeService,
    private val auditPublisher: AuditPublisher,
    private val totpPolicy: TotpPolicyProperties,
    private val pushPolicy: PushPolicyProperties,
) {

    fun enroll(request: EnrollDeviceRequest): EnrollDeviceResponse {
        val user = identityClient.findUser(request.userId)
        if (user == null || user.tenantId != request.tenantId) {
            throw UserNotFoundException(request.tenantId, request.userId)
        }

        val secretBytes = ByteArray(20)
        SecureRandom().nextBytes(secretBytes)
        val encrypted = totpCrypto.encrypt(request.tenantId, secretBytes)

        val device = repository.save(
            DeviceEntity(
                id = UUID.randomUUID(),
                tenantId = request.tenantId,
                userId = request.userId,
                status = DeviceStatus.PENDING,
                totpSecretCiphertext = encrypted.ciphertext,
                totpSecretNonce = encrypted.nonce,
                fcmToken = request.fcmToken,
            ),
        )

        audit(request.tenantId, request.userId, "device.enrolled", AuditResult.SUCCESS, device.id)

        val base32Secret = Base32.encode(secretBytes)
        return EnrollDeviceResponse(
            deviceId = device.id,
            status = device.status,
            totpSecret = base32Secret,
            provisioningUri = provisioningUri(user.email, base32Secret),
        )
    }

    /**
     * Self-service first-login enrollment (iam-auth-svc calls this when a
     * user submits password with no totpCode yet AND has no active device).
     * Idempotent and safe to call repeatedly before activation: a PENDING
     * device's secret is re-decrypted and re-revealed rather than minting a
     * new device every attempt (re-revealing a not-yet-activated secret is
     * safe -- nobody's trusted it as "the" device yet). Once ACTIVE, this
     * always returns alreadyActive=true and reveals nothing further.
     */
    fun ensurePending(request: EnsurePendingRequest): EnsurePendingResponse {
        val existing = repository.findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(request.tenantId, request.userId)
        if (existing != null && existing.status == DeviceStatus.ACTIVE) {
            return EnsurePendingResponse(alreadyActive = true)
        }
        if (existing != null) {
            val user = identityClient.findUser(request.userId)
                ?: throw UserNotFoundException(request.tenantId, request.userId)
            val secret = totpCrypto.decrypt(request.tenantId, existing.totpSecretCiphertext, existing.totpSecretNonce)
            val base32Secret = Base32.encode(secret)
            return EnsurePendingResponse(
                alreadyActive = false,
                deviceId = existing.id,
                totpSecret = base32Secret,
                provisioningUri = provisioningUri(user.email, base32Secret),
            )
        }

        val enrolled = try {
            enroll(EnrollDeviceRequest(request.tenantId, request.userId))
        } catch (ex: org.springframework.dao.DataIntegrityViolationException) {
            // Lost a race against a concurrent ensurePending call for the
            // same user (idx_devices_one_pending_per_user) -- the other
            // call's device is now "the" pending device; reveal that one
            // instead of ours so every concurrent caller converges on the
            // same secret.
            val winner = repository.findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(request.tenantId, request.userId)
                ?: throw ex
            val user = identityClient.findUser(request.userId)
                ?: throw UserNotFoundException(request.tenantId, request.userId)
            val secret = totpCrypto.decrypt(request.tenantId, winner.totpSecretCiphertext, winner.totpSecretNonce)
            val base32Secret = Base32.encode(secret)
            return EnsurePendingResponse(
                alreadyActive = false,
                deviceId = winner.id,
                totpSecret = base32Secret,
                provisioningUri = provisioningUri(user.email, base32Secret),
            )
        }
        return EnsurePendingResponse(
            alreadyActive = false,
            deviceId = enrolled.deviceId,
            totpSecret = enrolled.totpSecret,
            provisioningUri = enrolled.provisioningUri,
        )
    }

    /**
     * Backs the totpReenrollEveryLogin policy (iam-auth-svc): unlike
     * ensurePending, this ALWAYS discards any existing device -- active or
     * not -- and enrolls a fresh one, so a login under that policy never
     * reuses a previously-scanned QR. Audited the same way a brand-new
     * enroll() is; the prior device's disappearance is implied by the new
     * deviceId, not separately logged.
     */
    fun resetAndEnroll(request: ResetAndEnrollRequest): ResetAndEnrollResponse {
        repository.findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(request.tenantId, request.userId)?.let {
            repository.delete(it)
        }
        val enrolled = enroll(EnrollDeviceRequest(request.tenantId, request.userId))
        return ResetAndEnrollResponse(
            deviceId = enrolled.deviceId,
            totpSecret = enrolled.totpSecret,
            provisioningUri = enrolled.provisioningUri,
        )
    }

    fun verifyTotp(request: TotpVerifyRequest): TotpVerifyResponse {
        val device = repository.findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(request.tenantId, request.userId)
            ?: throw DeviceNotFoundException(request.tenantId, request.userId)

        val now = Instant.now()
        val lockedUntil = device.lockedUntil
        if (lockedUntil != null && now.isBefore(lockedUntil)) {
            audit(request.tenantId, request.userId, "device.totp_verified", AuditResult.DENIED, device.id, reason = "locked")
            return TotpVerifyResponse(valid = false, status = DeviceStatus2.LOCKED)
        }

        val secret = totpCrypto.decrypt(request.tenantId, device.totpSecretCiphertext, device.totpSecretNonce)
        val valid = TotpGenerator.verifyCode(
            secret, request.code, now, totpPolicy.stepSeconds, totpPolicy.digits, totpPolicy.driftWindowSteps,
        )

        if (valid) {
            device.failedTotpAttempts = 0
            device.lockedUntil = null
            if (device.status == DeviceStatus.PENDING) device.status = DeviceStatus.ACTIVE
            device.updatedAt = now
            repository.save(device)
            audit(request.tenantId, request.userId, "device.totp_verified", AuditResult.SUCCESS, device.id)
            return TotpVerifyResponse(valid = true, status = device.status.toVerifyStatus())
        }

        device.failedTotpAttempts += 1
        device.updatedAt = now
        return if (device.failedTotpAttempts >= totpPolicy.maxFailedAttempts) {
            device.lockedUntil = now.plus(totpPolicy.lockDuration)
            repository.save(device)
            audit(request.tenantId, request.userId, "device.locked", AuditResult.DENIED, device.id, reason = "too many failed TOTP attempts")
            TotpVerifyResponse(valid = false, status = DeviceStatus2.LOCKED)
        } else {
            repository.save(device)
            audit(request.tenantId, request.userId, "device.totp_verified", AuditResult.FAILURE, device.id, reason = "invalid code")
            TotpVerifyResponse(valid = false, status = device.status.toVerifyStatus())
        }
    }

    fun sendPush(request: PushSendRequest): PushSendResponse {
        val device = repository.findFirstByTenantIdAndUserIdAndFcmTokenIsNotNullOrderByCreatedAtDesc(request.tenantId, request.userId)
            ?: throw NoPushCapableDeviceException(request.tenantId, request.userId)

        val challenge = pushChallengeService.create(request.tenantId, request.userId, device.id)

        try {
            fcmClient.sendPushChallenge(device.fcmToken!!, challenge.challengeId)
        } catch (ex: FcmSendFailedException) {
            pushChallengeService.delete(challenge.challengeId)
            audit(request.tenantId, request.userId, "device.push_send_failed", AuditResult.FAILURE, device.id, reason = ex.message)
            throw ex
        }
        audit(request.tenantId, request.userId, "device.push_sent", AuditResult.SUCCESS, device.id, reason = "challengeId=${challenge.challengeId}")

        val result = awaitResolution(challenge.challengeId)
        if (result == PushResult.TIMEOUT) {
            audit(request.tenantId, request.userId, "device.push_timeout", AuditResult.DENIED, device.id, reason = "challengeId=${challenge.challengeId}")
            pushChallengeService.delete(challenge.challengeId)
        }
        return PushSendResponse(challenge.challengeId, result)
    }

    fun respondToPush(request: PushRespondRequest) {
        val challenge = pushChallengeService.find(request.challengeId)
            ?: throw ChallengeNotFoundException(request.challengeId)
        if (challenge.status != ChallengeStatus.PENDING) {
            throw ChallengeAlreadyResolvedException(request.challengeId)
        }
        pushChallengeService.resolve(request.challengeId, request.approve)

        audit(
            challenge.tenantId, challenge.userId, "device.push_responded",
            if (request.approve) AuditResult.SUCCESS else AuditResult.DENIED,
            challenge.deviceId, reason = if (request.approve) "approved" else "denied",
        )
    }

    /** Polls Valkey until the challenge resolves or [PushPolicyProperties.waitTimeoutSeconds] elapses. */
    private fun awaitResolution(challengeId: UUID): PushResult {
        val deadline = Instant.now().plusSeconds(pushPolicy.waitTimeoutSeconds)
        while (Instant.now().isBefore(deadline)) {
            val current = pushChallengeService.find(challengeId) ?: return PushResult.TIMEOUT
            when (current.status) {
                ChallengeStatus.APPROVED -> return PushResult.APPROVED
                ChallengeStatus.DENIED -> return PushResult.DENIED
                ChallengeStatus.PENDING -> Thread.sleep(POLL_INTERVAL_MS)
            }
        }
        return PushResult.TIMEOUT
    }

    private fun provisioningUri(email: String, base32Secret: String): String {
        // Percent-encoded per RFC 3986, not URLEncoder's form-encoding ("+"
        // for space): this goes in the URI's path segment, not a query
        // string, so a literal "+" would be read back as "+", not a space,
        // by any authenticator app that decodes it correctly.
        val label = java.net.URLEncoder.encode("IAM Platform:$email", "UTF-8").replace("+", "%20")
        val issuer = URLEncoder.encode("IAM Platform", "UTF-8")
        return "otpauth://totp/$label?secret=$base32Secret&issuer=$issuer&digits=${totpPolicy.digits}&period=${totpPolicy.stepSeconds}"
    }

    private fun audit(tenantId: UUID, userId: UUID, action: String, result: AuditResult, deviceId: UUID, reason: String? = null) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.USER,
                actorId = userId.toString(),
                action = action,
                result = result,
                reason = reason,
                deviceId = deviceId.toString(),
            ),
        )
    }

    companion object {
        private const val POLL_INTERVAL_MS = 1000L
    }
}
