package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Modifying
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID

/*
 * Device-bound sign-in (docs/specs/device-bound-signin-SPEC.md, PDF section 4.2): a sign-in may carry PROOF that it
 * comes from an enrolled laptop. The platform issues a one-time challenge; the agent on the laptop signs it with the
 * device key; this service verifies the signature against the key registered at enrollment. A deviceId alone is never
 * trusted.
 */

@Entity
@Table(name = "iam_device_login_challenges")
class DeviceLoginChallengeEntity(
    @Id @Column(name = "id") var id: UUID,
    @Column(name = "tenant_id", nullable = false) var tenantId: UUID,
    @Column(name = "nonce", nullable = false) var nonce: String,
    @Column(name = "expires_at", nullable = false) var expiresAt: Instant,
    @Column(name = "consumed_at") var consumedAt: Instant? = null,
    @Column(name = "created_at", nullable = false) var createdAt: Instant = Instant.now(),
)

interface DeviceLoginChallengeRepository : JpaRepository<DeviceLoginChallengeEntity, UUID> {
    /** Atomic single-use: returns 1 only for the first caller. */
    @Modifying
    @Query("update DeviceLoginChallengeEntity c set c.consumedAt = :now where c.id = :id and c.consumedAt is null")
    fun consume(@Param("id") id: UUID, @Param("now") now: Instant): Int

    /** Housekeeping: challenges are useless once expired, and anyone can ask for one, so the table must not grow without bound. */
    @Modifying
    @Query("delete from DeviceLoginChallengeEntity c where c.expiresAt < :cutoff")
    fun deleteExpiredBefore(@Param("cutoff") cutoff: Instant): Int
}

data class DeviceChallengeRequest(@field:NotNull val tenantId: UUID)

data class DeviceChallengeResponse(val challengeId: UUID, val nonce: String, val expiresAt: Instant)

data class DeviceChallengeVerifyRequest(
    // The user auth-svc has ALREADY authenticated by password. The device must belong to this user.
    @field:NotNull val userId: UUID,
    @field:NotNull val deviceId: UUID,
    @field:NotBlank val signature: String,
    @field:NotBlank val origin: String,
)

data class DeviceChallengeVerifyResponse(val deviceId: UUID, val assuranceLevel: String)

@Service
class DeviceLoginProofService(
    private val challenges: DeviceLoginChallengeRepository,
    private val devices: IamDeviceRepository,
    private val keys: DeviceKeyRepository,
    private val signatureVerifier: DeviceSignatureVerifier,
    private val auditPublisher: AuditPublisher,
) {
    private val random = SecureRandom()

    @Transactional
    fun issue(tenantId: UUID): DeviceChallengeResponse {
        val nonce = ByteArray(32).also(random::nextBytes).let { Base64.getUrlEncoder().withoutPadding().encodeToString(it) }
        val now = Instant.now()
        challenges.deleteExpiredBefore(now.minus(CLEANUP_AFTER))
        val entity = DeviceLoginChallengeEntity(UUID.randomUUID(), tenantId, nonce, now.plus(CHALLENGE_LIFETIME))
        challenges.save(entity)
        return DeviceChallengeResponse(entity.id, entity.nonce, entity.expiresAt)
    }

    /**
     * Verifies the proof. The challenge is consumed FIRST and unconditionally, so a nonce can never be retried after a
     * failed attempt. Every failure is the same exception type (-> HTTP 401): the caller learns "not proven", not why.
     */
    @Transactional
    fun verify(challengeId: UUID, request: DeviceChallengeVerifyRequest, sourceIp: String?): DeviceChallengeVerifyResponse {
        val now = Instant.now()
        val challenge = challenges.findById(challengeId).orElse(null)
        if (challenge == null) throw rejected(null, request.userId, request.deviceId, "unknown challenge", sourceIp)
        val firstUse = challenges.consume(challengeId, now) == 1
        if (!firstUse) throw rejected(challenge, request.userId, request.deviceId, "challenge already used", sourceIp)
        if (now.isAfter(challenge.expiresAt)) throw rejected(challenge, request.userId, request.deviceId, "challenge expired", sourceIp)

        val device = devices.findById(request.deviceId).orElse(null)
        // Same tenant AND same user: a laptop enrolled by someone else cannot vouch for this sign-in.
        if (device == null || device.tenantId != challenge.tenantId || device.userId != request.userId) {
            throw rejected(challenge, request.userId, request.deviceId, "device does not belong to this user", sourceIp)
        }
        if (device.lifecycleStatus in DEAD_STATES) throw rejected(challenge, request.userId, request.deviceId, "device is ${device.lifecycleStatus.lowercase()}", sourceIp)

        val key = keys.findByDeviceIdAndStatus(device.id, KeyStatus.ACTIVE.name)
            ?: throw rejected(challenge, request.userId, request.deviceId, "device has no active key", sourceIp)
        val signedData = canonicalPayload(challenge, device.id, request.origin).toByteArray(Charsets.UTF_8)
        val valid = try {
            signatureVerifier.verify(key.publicKey, key.keyAlgorithm, signedData, request.signature)
        } catch (ex: RuntimeException) {
            false
        }
        if (!valid) throw rejected(challenge, request.userId, request.deviceId, "signature did not verify", sourceIp)

        audit(challenge.tenantId, request.userId, device.id, "device.login_proof.accepted", AuditResult.SUCCESS, null, sourceIp)
        return DeviceChallengeVerifyResponse(device.id, key.assuranceLevel)
    }

    private fun rejected(challenge: DeviceLoginChallengeEntity?, userId: UUID, deviceId: UUID, reason: String, sourceIp: String?): DeviceProofOfPossessionException {
        if (challenge != null) audit(challenge.tenantId, userId, deviceId, "device.login_proof.rejected", AuditResult.DENIED, reason, sourceIp)
        return DeviceProofOfPossessionException("Device proof rejected")
    }

    private fun audit(tenantId: UUID, userId: UUID, deviceId: UUID, action: String, result: AuditResult, reason: String?, sourceIp: String?) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.USER,
                actorId = userId.toString(),
                action = action,
                result = result,
                reason = reason,
                sourceIp = sourceIp,
                deviceId = deviceId.toString(),
            ),
        )
    }

    companion object {
        // 120 s, not 60: the push sign-in path can wait up to 60 s for the phone before the proof is verified.
        val CHALLENGE_LIFETIME: Duration = Duration.ofSeconds(120)
        private val CLEANUP_AFTER: Duration = Duration.ofHours(1)
        private val DEAD_STATES = setOf("REVOKED", "REJECTED", "DECOMMISSIONED")

        /**
         * The exact bytes the agent signs. Domain-separated (the leading label) so a signature made for this purpose can
         * never be replayed as, say, a heartbeat signature, and bound to tenant, user, device, challenge, nonce and the
         * origin of the page that asked.
         */
        fun canonicalPayload(c: DeviceLoginChallengeEntity, deviceId: UUID, origin: String): String =
            listOf("iam-device-login-v1", c.tenantId, deviceId, c.id, c.nonce, origin).joinToString("\n")
    }
}

/**
 * Does this tenant have any app that requires a trusted device? The login page only talks to the endpoint agent on the
 * user's laptop when the answer is yes, so a tenant that never flags an app sees no change to its sign-in page at all.
 */
@Service
class TrustedDeviceRequirementService(
    private val oidcClients: OidcClientRepository,
    private val samlSps: SamlSpRepository,
) {
    fun tenantRequires(tenantId: UUID): Boolean =
        oidcClients.existsByTenantIdAndRequireTrustedDeviceTrue(tenantId) || samlSps.existsByTenantIdAndRequireTrustedDeviceTrue(tenantId)
}

data class TrustedDeviceRequiredResponse(val required: Boolean)

/**
 * Internal, service-to-service (iam-login-portal asks for a challenge; iam-auth-svc verifies the proof during login).
 * Not routed by the public proxy. Same exposure class as /internal/devices -- see OQ-24 / OQ-29.
 */
@RestController
@RequestMapping("/internal/device-challenges")
class InternalDeviceChallengeController(
    private val service: DeviceLoginProofService,
    private val requirement: TrustedDeviceRequirementService,
) {

    @GetMapping("/required")
    fun required(@RequestParam tenantId: UUID): ResponseEntity<TrustedDeviceRequiredResponse> =
        ResponseEntity.ok(TrustedDeviceRequiredResponse(requirement.tenantRequires(tenantId)))


    @PostMapping
    fun issue(@Valid @RequestBody request: DeviceChallengeRequest): ResponseEntity<DeviceChallengeResponse> =
        ResponseEntity.ok(service.issue(request.tenantId))

    @PostMapping("/{challengeId}/verify")
    fun verify(
        @PathVariable challengeId: UUID,
        @Valid @RequestBody request: DeviceChallengeVerifyRequest,
    ): ResponseEntity<DeviceChallengeVerifyResponse> = ResponseEntity.ok(service.verify(challengeId, request, null))
}

/**
 * The "trusted device required" rule for an application (decision D2/D4 in the spec). Called after the normal group
 * check allowed the user in; returns a denial, or null when it has no objection. Applies to administrators too -- an
 * admin without an approved, compliant laptop must not reach a flagged app either.
 */
@Service
class TrustedDeviceGate(
    private val oidcClients: OidcClientRepository,
    private val samlSps: SamlSpRepository,
    private val devices: IamDeviceRepository,
    private val posture: DevicePostureRepository,
    private val auditPublisher: AuditPublisher,
) {
    fun check(tenantId: UUID, userId: UUID, appKind: String, appId: UUID, sessionDeviceId: String?): AppAccessResponse? {
        // (requires a trusted device, also lets a pending laptop in)
        val (required, allowPending) = when (appKind.lowercase()) {
            "oidc" -> oidcClients.findById(appId).map { it.requireTrustedDevice to it.allowPendingDevice }.orElse(false to false)
            "saml" -> samlSps.findById(appId).map { it.requireTrustedDevice to it.allowPendingDevice }.orElse(false to false)
            else -> false to false
        }
        if (!required) return null
        // Spec 6.4: an app's own policy decides whether a laptop still awaiting approval may open it. Anything else that is not
        // APPROVED (suspended, revoked, rejected, non-compliant lifecycle...) stays refused, whatever this setting says.
        val acceptedStates =
            if (allowPending) setOf(DeviceLifecycleStatus.APPROVED.name, DeviceLifecycleStatus.PENDING_APPROVAL.name) else setOf(DeviceLifecycleStatus.APPROVED.name)

        val deviceId = sessionDeviceId?.let { runCatching { UUID.fromString(it) }.getOrNull() }
        val device = deviceId?.let { devices.findById(it).orElse(null) }?.takeIf { it.tenantId == tenantId && it.userId == userId }
        // iam-login-portal recognises these phrases to show a specific page (lib/errorCodes.ts, accessDenialReason).
        // Changing the wording only makes that page fall back to the generic message; keep them in step anyway.
        val reason = when {
            deviceId == null -> "This app needs a managed, approved device. Install the endpoint agent on your laptop and sign in again."
            device == null -> "Your device is no longer registered. Enroll it again."
            device.lifecycleStatus !in acceptedStates ->
                "Your device is not approved (${device.lifecycleStatus.lowercase().replace('_', ' ')}). Ask your administrator."
            posture.findById(device.id).map { it.postureStatus }.orElse(null) == PostureStatus.NON_COMPLIANT.name ->
                "Your device does not meet the security requirements. Your administrator can see which checks failed."
            else -> null
        } ?: return null

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.USER,
                actorId = userId.toString(),
                action = "app.access.denied_untrusted_device",
                result = AuditResult.DENIED,
                reason = reason,
                deviceId = deviceId?.toString(),
            ),
        )
        return AppAccessResponse(false, reason)
    }
}
