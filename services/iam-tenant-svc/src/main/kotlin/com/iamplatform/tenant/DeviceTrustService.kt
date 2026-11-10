package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import com.iamplatform.servicekit.vault.OpenBaoPkiClient
import com.iamplatform.servicekit.vault.OpenBaoTransitClient
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID

/**
 * Tenant-level device-trust policy defaults (Endpoint Device Trust spec
 * Appendix A). A tenant can override these by writing an
 * iam_device_policies row (DevicePolicyController, not built in Phase 1 --
 * admin console currently only reads the effective policy); until one
 * exists, every tenant gets these defaults.
 */
private data class DeviceTenantPolicyDefaults(
    val autoApproveCorporate: Boolean = true,
    val maxDevicesPerUser: Int = 5,
    val heartbeatIntervalSeconds: Int = 300,
    val postureIntervalSeconds: Int = 900,
    val agentFailureMode: FailureMode = FailureMode.RISK_BASED,
    val certificateTtlSeconds: Long = Duration.ofDays(90).seconds,
    val enrollmentTransactionTtlSeconds: Long = 300,
)

private val DEFAULT_POLICY = DeviceTenantPolicyDefaults()

// Devices in these states never satisfy device-trust requirements, and are
// excluded from the per-user device-count limit so a user can re-enroll
// after a rejection/revocation without hitting the cap artificially.
private val TERMINAL_STATUSES = listOf(
    DeviceLifecycleStatus.REJECTED.name, DeviceLifecycleStatus.REVOKED.name, DeviceLifecycleStatus.DECOMMISSIONED.name,
)

@Service
class DeviceTrustService(
    private val deviceRepository: IamDeviceRepository,
    private val hardwareRepository: DeviceHardwareRepository,
    private val keyRepository: DeviceKeyRepository,
    private val certificateRepository: DeviceCertificateRepository,
    private val approvalRepository: DeviceApprovalRepository,
    private val postureRepository: DevicePostureRepository,
    private val heartbeatRepository: DeviceHeartbeatRepository,
    private val eventRepository: DeviceEventRepository,
    private val policyRepository: DevicePolicyRepository,
    private val appPolicyRepository: DeviceAppPolicyRepository,
    private val enrollmentTransactionRepository: DeviceEnrollmentTransactionRepository,
    private val signatureVerifier: DeviceSignatureVerifier,
    private val pkiClient: OpenBaoPkiClient,
    private val transitClient: OpenBaoTransitClient,
    private val auditPublisher: AuditPublisher,
) {
    private val secureRandom = SecureRandom()

    // ---- Enrollment (Section 6.1) ----

    /**
     * Step 4 of the enrollment sequence: the caller already proved a live
     * IAM session (X-Session-Token, checked by the controller via
     * AdminAccessGuard.requireValidSession) -- this mints the short-lived,
     * single-use authorization the agent exchanges for a device record,
     * without the agent ever seeing a password (Section 6.1 step 3).
     */
    @Transactional
    fun startEnrollment(tenantId: UUID, userId: UUID, keyThumbprint: String): EnrollmentStartResponse {
        val nonce = Base64.getEncoder().encodeToString(ByteArray(32).also { secureRandom.nextBytes(it) })
        val now = Instant.now()
        val tx = DeviceEnrollmentTransactionEntity(
            id = UUID.randomUUID(),
            tenantId = tenantId,
            userId = userId,
            nonce = nonce,
            createdAt = now,
            expiresAt = now.plusSeconds(DEFAULT_POLICY.enrollmentTransactionTtlSeconds),
            keyThumbprint = keyThumbprint,
        )
        enrollmentTransactionRepository.save(tx)
        return EnrollmentStartResponse(tx.id, nonce, tx.expiresAt)
    }

    // noRollbackFor: these are thrown after the transaction is marked consumed but before any device
    // rows are written -- rolling back would silently un-burn a transaction that just failed a
    // proof-of-possession or key-binding check, letting an attacker retry it.
    @Transactional(noRollbackFor = [DeviceProofOfPossessionException::class, EnrollmentTransactionInvalidException::class])
    fun completeEnrollment(request: EnrollmentCompleteRequest, sourceIp: String?): EnrollmentCompleteResponse {
        val tx = enrollmentTransactionRepository.findById(request.enrollmentTransactionId).orElse(null)
            ?: throw EnrollmentTransactionInvalidException("Unknown enrollment transaction")
        if (tx.consumedAt != null) throw EnrollmentTransactionInvalidException("Enrollment transaction already used")
        if (tx.expiresAt.isBefore(Instant.now())) throw EnrollmentTransactionInvalidException("Enrollment transaction expired")

        // Every failure from here on burns the transaction -- a stolen id gets at most one guess.
        tx.consumedAt = Instant.now()
        enrollmentTransactionRepository.save(tx)

        // Key binding: only the key whose thumbprint the agent committed to before sign-in may complete
        // this transaction (see V10 migration).
        val expectedThumbprint = tx.keyThumbprint
            ?: throw EnrollmentTransactionInvalidException("Enrollment transaction is not bound to a device key")
        val submittedThumbprint = try {
            DeviceKeyThumbprint.of(Base64.getDecoder().decode(request.publicKey))
        } catch (ex: IllegalArgumentException) {
            throw DeviceProofOfPossessionException("Malformed device public key")
        }
        if (!DeviceKeyThumbprint.matches(expectedThumbprint, submittedThumbprint)) {
            throw DeviceProofOfPossessionException("Public key does not match the key this enrollment was started for")
        }

        // Proof of possession: the device must have signed this exact transaction's nonce with the
        // private key matching the public key it is now registering (Section 4.2/5.3).
        val signed = signatureVerifier.verify(request.publicKey, request.keyAlgorithm, tx.nonce.toByteArray(Charsets.UTF_8), request.proofOfPossession)
        if (!signed) throw DeviceProofOfPossessionException("Proof-of-possession signature did not verify")

        val ownership = DeviceOwnership.valueOf(request.ownership)
        val activeDeviceCount = deviceRepository.countByTenantIdAndUserIdAndLifecycleStatusNotIn(tx.tenantId, tx.userId, TERMINAL_STATUSES)
        if (activeDeviceCount >= DEFAULT_POLICY.maxDevicesPerUser) {
            throw DeviceLimitExceededException("Maximum of ${DEFAULT_POLICY.maxDevicesPerUser} registered devices per user reached")
        }

        val approvalMode = if (ownership == DeviceOwnership.CORPORATE && DEFAULT_POLICY.autoApproveCorporate) ApprovalMode.AUTOMATIC else ApprovalMode.MANUAL
        val now = Instant.now()
        val deviceId = UUID.randomUUID()
        val device = IamDeviceEntity(
            id = deviceId,
            tenantId = tx.tenantId,
            userId = tx.userId,
            deviceInstanceId = request.deviceInstanceId,
            platform = request.platform,
            hostname = request.hostname,
            ownership = request.ownership,
            lifecycleStatus = DeviceLifecycleStatus.PENDING_APPROVAL.name,
            agentVersion = request.agentVersion,
            createdAt = now,
            updatedAt = now,
        )
        deviceRepository.save(device)

        hardwareRepository.save(
            DeviceHardwareEntity(
                deviceId = deviceId,
                fingerprintVersion = request.fingerprintVersion,
                fingerprintHash = request.fingerprintHash,
                hardwareUuidHash = request.hardwareUuidHash,
                serialHash = request.serialHash,
                manufacturer = request.manufacturer,
                model = request.model,
                osVersion = request.osVersion,
            ),
        )

        val keyId = UUID.randomUUID()
        keyRepository.save(
            DeviceKeyEntity(
                id = keyId,
                deviceId = deviceId,
                publicKey = request.publicKey,
                keyAlgorithm = request.keyAlgorithm,
                assuranceLevel = request.assuranceLevel,
                status = KeyStatus.ACTIVE.name,
                createdAt = now,
            ),
        )

        publishDeviceEvent(tx.tenantId, deviceId, "device.enrollment.submitted", EventSeverity.INFO, null)

        var certificatePem: String? = null
        var issuingCaPem: String? = null
        var certificateStatus = "NOT_ISSUED"

        if (approvalMode == ApprovalMode.AUTOMATIC) {
            recordApproval(deviceId, ApprovalMode.AUTOMATIC, ApprovalDecision.APPROVED, "system", null)
            device.lifecycleStatus = DeviceLifecycleStatus.APPROVED.name
            device.updatedAt = Instant.now()
            deviceRepository.save(device)
            val issued = issueCertificateFor(device, keyId)
            certificatePem = issued.certificatePem
            issuingCaPem = issued.issuingCaPem
            certificateStatus = CertificateStatus.ACTIVE.name
        } else {
            auditPublisher.publish(
                AuditEvent(
                    correlationId = CorrelationId.get(),
                    tenantId = tx.tenantId,
                    actorType = ActorType.AGENT,
                    actorId = tx.userId.toString(),
                    action = "device.enrollment.submitted",
                    result = AuditResult.SUCCESS,
                    reason = "awaiting manual approval",
                    sourceIp = sourceIp,
                    deviceId = deviceId.toString(),
                ),
            )
        }

        val policyVersion = policyRepository.findTopByTenantIdOrderByVersionDesc(tx.tenantId)?.version ?: 0

        return EnrollmentCompleteResponse(
            deviceId = deviceId,
            status = device.lifecycleStatus,
            approvalType = approvalMode.name,
            certificateStatus = certificateStatus,
            certificatePem = certificatePem,
            issuingCaPem = issuingCaPem,
            policyVersion = policyVersion,
            message = if (approvalMode == ApprovalMode.AUTOMATIC) "Device approved and certificate issued" else "Device registration submitted",
        )
    }

    // ---- Inventory (Admin Console, Section 13) ----

    fun listDevices(tenantId: UUID): List<DeviceSummaryResponse> =
        deviceRepository.findByTenantId(tenantId).map { toSummary(it) }

    fun getDevice(tenantId: UUID, deviceId: UUID): DeviceSummaryResponse =
        toSummary(requireDevice(tenantId, deviceId))

    private fun toSummary(device: IamDeviceEntity): DeviceSummaryResponse {
        val posture = postureRepository.findById(device.id).orElse(null)
        val cert = certificateRepository.findByDeviceIdAndStatus(device.id, CertificateStatus.ACTIVE.name)
        return DeviceSummaryResponse(
            id = device.id,
            tenantId = device.tenantId,
            userId = device.userId,
            hostname = device.hostname,
            platform = device.platform,
            ownership = device.ownership,
            lifecycleStatus = device.lifecycleStatus,
            agentVersion = device.agentVersion,
            lastSeenAt = device.lastSeenAt,
            postureStatus = posture?.postureStatus,
            certificateStatus = cert?.status,
            createdAt = device.createdAt,
        )
    }

    // ---- Approval actions (Section 6.3, admin-gated by the controller) ----

    @Transactional
    fun approve(tenantId: UUID, deviceId: UUID, actorId: String, reason: String?, sourceIp: String?) {
        val device = requireDevice(tenantId, deviceId)
        device.lifecycleStatus = DeviceLifecycleStatus.APPROVED.name
        device.updatedAt = Instant.now()
        deviceRepository.save(device)
        recordApproval(deviceId, ApprovalMode.MANUAL, ApprovalDecision.APPROVED, actorId, reason)
        val activeKey = keyRepository.findByDeviceIdAndStatus(deviceId, KeyStatus.ACTIVE.name)
        if (activeKey != null && certificateRepository.findByDeviceIdAndStatus(deviceId, CertificateStatus.ACTIVE.name) == null) {
            issueCertificateFor(device, activeKey.id)
        }
        audit(tenantId, deviceId, actorId, "device.approved", AuditResult.SUCCESS, reason, sourceIp)
    }

    @Transactional
    fun reject(tenantId: UUID, deviceId: UUID, actorId: String, reason: String?, sourceIp: String?) {
        val device = requireDevice(tenantId, deviceId)
        device.lifecycleStatus = DeviceLifecycleStatus.REJECTED.name
        device.updatedAt = Instant.now()
        deviceRepository.save(device)
        recordApproval(deviceId, ApprovalMode.MANUAL, ApprovalDecision.REJECTED, actorId, reason)
        audit(tenantId, deviceId, actorId, "device.rejected", AuditResult.SUCCESS, reason, sourceIp)
    }

    @Transactional
    fun suspend(tenantId: UUID, deviceId: UUID, actorId: String, reason: String?, sourceIp: String?) {
        val device = requireDevice(tenantId, deviceId)
        device.lifecycleStatus = DeviceLifecycleStatus.SUSPENDED.name
        device.updatedAt = Instant.now()
        deviceRepository.save(device)
        recordApproval(deviceId, ApprovalMode.MANUAL, ApprovalDecision.SUSPENDED, actorId, reason)
        audit(tenantId, deviceId, actorId, "device.suspended", AuditResult.SUCCESS, reason, sourceIp)
    }

    /**
     * Permanently revokes trust. Revokes the active certificate in OpenBao
     * (Section 16 "Certificate revocation not propagating to active
     * sessions" is explicitly a threat to model) -- the PEP's own
     * continuous-enforcement check (AP-2) is what actually terminates any
     * already-issued session on its next request; this call only stops any
     * *new* device authentication from succeeding.
     */
    @Transactional
    fun revoke(tenantId: UUID, deviceId: UUID, actorId: String, reason: String?, sourceIp: String?) {
        val device = requireDevice(tenantId, deviceId)
        device.lifecycleStatus = DeviceLifecycleStatus.REVOKED.name
        device.updatedAt = Instant.now()
        deviceRepository.save(device)
        recordApproval(deviceId, ApprovalMode.MANUAL, ApprovalDecision.REVOKED, actorId, reason)
        val activeCert = certificateRepository.findByDeviceIdAndStatus(deviceId, CertificateStatus.ACTIVE.name)
        if (activeCert != null) {
            try {
                pkiClient.revokeCertificate(activeCert.serialNumber)
            } finally {
                activeCert.status = CertificateStatus.REVOKED.name
                activeCert.revokedAt = Instant.now()
                activeCert.revokedReason = reason
                certificateRepository.save(activeCert)
            }
        }
        audit(tenantId, deviceId, actorId, "device.revoked", AuditResult.SUCCESS, reason, sourceIp)
    }

    private fun recordApproval(deviceId: UUID, mode: ApprovalMode, decision: ApprovalDecision, actorId: String, reason: String?) {
        approvalRepository.save(
            DeviceApprovalEntity(
                id = UUID.randomUUID(),
                deviceId = deviceId,
                approvalMode = mode.name,
                decision = decision.name,
                actorId = actorId,
                reason = reason,
            ),
        )
    }

    private fun issueCertificateFor(device: IamDeviceEntity, keyId: UUID): com.iamplatform.servicekit.vault.IssuedCertificate {
        val issued = pkiClient.issueCertificate(
            role = "endpoint-device",
            commonName = device.id.toString(),
            tenantId = device.tenantId.toString(),
            deviceId = device.id.toString(),
            ttlSeconds = DEFAULT_POLICY.certificateTtlSeconds,
        )
        certificateRepository.save(
            DeviceCertificateEntity(
                id = UUID.randomUUID(),
                deviceId = device.id,
                keyId = keyId,
                issuerKeyId = "endpoint-device",
                serialNumber = issued.serialNumber,
                fingerprint = issued.serialNumber, // OpenBao's serial doubles as a stable, unique reference
                notBefore = issued.notBefore,
                notAfter = issued.notAfter,
                status = CertificateStatus.ACTIVE.name,
            ),
        )
        publishDeviceEvent(device.tenantId, device.id, "device.certificate.issued", EventSeverity.INFO, null)
        return issued
    }

    // ---- Device-authenticated calls (heartbeat/posture/events/compliance/policy) ----

    /**
     * Every device-authenticated endpoint below requires this: a signature
     * over "deviceId:timestamp" made with the device's currently active
     * key, and a timestamp within a tight freshness window. This is the
     * "nonce-based signed challenge" alternative to mTLS the spec's Section
     * 4.2 explicitly allows. The freshness window (not a true per-call
     * nonce) is the Phase 1 replay-protection mechanism -- TLS 1.3 in
     * transit (Section 16) protects the body itself; a full per-request
     * server-issued nonce is a Phase 2 hardening item.
     */
    fun requireDeviceProof(tenantId: UUID, deviceId: UUID, timestamp: Instant, signatureBase64: String): IamDeviceEntity {
        val device = requireDevice(tenantId, deviceId)
        if (Duration.between(timestamp, Instant.now()).abs() > Duration.ofSeconds(120)) {
            throw DeviceProofOfPossessionException("Request timestamp outside the allowed freshness window")
        }
        val key = keyRepository.findByDeviceIdAndStatus(deviceId, KeyStatus.ACTIVE.name)
            ?: throw DeviceProofOfPossessionException("Device has no active key")
        val signedData = "$deviceId:$timestamp".toByteArray(Charsets.UTF_8)
        if (!signatureVerifier.verify(key.publicKey, key.keyAlgorithm, signedData, signatureBase64)) {
            throw DeviceProofOfPossessionException("Device signature did not verify")
        }
        return device
    }

    @Transactional
    fun heartbeat(tenantId: UUID, deviceId: UUID, request: DeviceHeartbeatRequest) {
        val device = requireDevice(tenantId, deviceId)
        val now = Instant.now()
        device.lastSeenAt = now
        device.agentVersion = request.agentVersion
        deviceRepository.save(device)

        val existing = heartbeatRepository.findById(deviceId).orElse(null)
        if (existing != null) {
            existing.lastSeenAt = now
            existing.agentVersion = request.agentVersion
            existing.policyVersion = request.policyVersion
            existing.healthStatus = request.healthStatus
            heartbeatRepository.save(existing)
        } else {
            heartbeatRepository.save(DeviceHeartbeatEntity(deviceId, now, request.agentVersion, request.policyVersion, request.healthStatus))
        }

        if (request.healthStatus == HealthStatus.TAMPERED.name) {
            publishDeviceEvent(tenantId, deviceId, "device.tampering", EventSeverity.CRITICAL, null)
        }
    }

    @Transactional
    fun updatePosture(tenantId: UUID, deviceId: UUID, request: DevicePostureRequest) {
        requireDevice(tenantId, deviceId)
        val now = Instant.now()
        val existing = postureRepository.findById(deviceId).orElse(null)
        if (existing != null) {
            existing.postureStatus = request.postureStatus
            existing.riskScore = request.riskScore
            existing.signalsJson = request.signalsJson
            existing.evaluatedAt = now
            postureRepository.save(existing)
        } else {
            postureRepository.save(DevicePostureEntity(deviceId, request.postureStatus, request.riskScore, request.signalsJson, now))
        }
        if (request.postureStatus == PostureStatus.NON_COMPLIANT.name) {
            val device = requireDevice(tenantId, deviceId)
            if (device.lifecycleStatus == DeviceLifecycleStatus.APPROVED.name) {
                device.lifecycleStatus = DeviceLifecycleStatus.NON_COMPLIANT.name
                device.updatedAt = now
                deviceRepository.save(device)
            }
            publishDeviceEvent(tenantId, deviceId, "device.noncompliant", EventSeverity.WARNING, request.signalsJson)
        }
    }

    @Transactional
    fun recordEvent(tenantId: UUID, deviceId: UUID, request: DeviceEventRequest) {
        requireDevice(tenantId, deviceId)
        publishDeviceEvent(tenantId, deviceId, request.eventType, EventSeverity.valueOf(request.severity), request.metadataJson)
    }

    @Transactional
    fun recordCompliance(tenantId: UUID, deviceId: UUID, request: DeviceComplianceRequest) {
        updatePosture(tenantId, deviceId, DevicePostureRequest(request.postureStatus, null, request.signalsJson))
    }

    private fun publishDeviceEvent(tenantId: UUID, deviceId: UUID, eventType: String, severity: EventSeverity, metadataJson: String?) {
        eventRepository.save(
            DeviceEventEntity(
                id = UUID.randomUUID(),
                tenantId = tenantId,
                deviceId = deviceId,
                eventType = eventType,
                severity = severity.name,
                metadataJson = metadataJson,
            ),
        )
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.AGENT,
                actorId = deviceId.toString(),
                action = eventType,
                result = AuditResult.SUCCESS,
                deviceId = deviceId.toString(),
            ),
        )
    }

    // ---- Signed policy fetch (Section 10.3, device-authenticated) ----

    fun fetchPolicy(tenantId: UUID, deviceId: UUID): DevicePolicyResponse {
        val device = requireDevice(tenantId, deviceId)
        val policyEntity = policyRepository.findTopByTenantIdOrderByVersionDesc(tenantId)
        val policyId = policyEntity?.id ?: deviceId // stable placeholder until a tenant has configured one
        val policyVersion = policyEntity?.version ?: 0
        val apps = policyEntity?.let { appPolicyRepository.findByPolicyId(it.id) }?.map {
            DeviceAppPolicyResponse(it.applicationId, it.pendingAccess, it.offlineAccess, it.offlineGraceSeconds, it.failureMode)
        } ?: emptyList()

        val now = Instant.now()
        val expiresAt = now.plusSeconds(DEFAULT_POLICY.heartbeatIntervalSeconds.toLong() * 3)
        val canonical = canonicalPolicyEncoding(policyId, policyVersion, now, expiresAt, device.lifecycleStatus, apps)
        val signature = transitClient.sign("device-policy", canonical.toByteArray(Charsets.UTF_8))

        return DevicePolicyResponse(
            policyId = policyId,
            policyVersion = policyVersion,
            issuedAt = now,
            expiresAt = expiresAt,
            deviceStatus = device.lifecycleStatus,
            heartbeatIntervalSeconds = DEFAULT_POLICY.heartbeatIntervalSeconds,
            postureIntervalSeconds = DEFAULT_POLICY.postureIntervalSeconds,
            agentFailureMode = DEFAULT_POLICY.agentFailureMode.name,
            applications = apps,
            signature = signature,
        )
    }

    // Deterministic, field-order-fixed encoding -- the Rust agent's
    // policy-verifier crate must reproduce this exact string to check the
    // signature OpenBao's transit engine returned. Documented here as the
    // single source of truth for that format; change both sides together.
    private fun canonicalPolicyEncoding(
        policyId: UUID,
        version: Int,
        issuedAt: Instant,
        expiresAt: Instant,
        deviceStatus: String,
        apps: List<DeviceAppPolicyResponse>,
    ): String {
        val appsPart = apps.joinToString(";") { "${it.applicationId}:${it.pendingAccess}:${it.offlineAccess}:${it.offlineGraceSeconds}:${it.failureMode}" }
        return "$policyId|$version|${issuedAt.epochSecond}|${expiresAt.epochSecond}|$deviceStatus|$appsPart"
    }

    private fun requireDevice(tenantId: UUID, deviceId: UUID): IamDeviceEntity {
        val device = deviceRepository.findById(deviceId).orElse(null) ?: throw DeviceNotFoundException(deviceId)
        if (device.tenantId != tenantId) throw DeviceNotFoundException(deviceId) // cross-tenant lookup must look identical to "not found" (Section 16)
        return device
    }

    private fun audit(tenantId: UUID, deviceId: UUID, actorId: String, action: String, result: AuditResult, reason: String?, sourceIp: String?) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.ADMIN,
                actorId = actorId,
                action = action,
                result = result,
                reason = reason,
                sourceIp = sourceIp,
                deviceId = deviceId.toString(),
            ),
        )
    }
}
