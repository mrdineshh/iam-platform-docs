package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import com.iamplatform.servicekit.vault.OpenBaoPkiClient
import com.iamplatform.servicekit.vault.OpenBaoTransitClient
import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.security.SecureRandom
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.UUID
import tools.jackson.databind.ObjectMapper

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
    private val objectMapper: ObjectMapper,
    // Off by default: the posture verdict is recorded and shown, but does not change what a device may
    // do. Turning it on would suspend access for any approved device that fails the default rules
    // (e.g. a laptop without BitLocker), which an operator must opt into knowingly.
    @Value("\${iam.device.enforce-posture:false}") private val enforcePosture: Boolean,
    // Off by default, on purpose. OpenBaoPkiClient.issueCertificate uses the PKI "issue" API, which makes
    // OpenBao generate a NEW key pair and return a certificate for that key -- the device's own enrolled key
    // is never involved, so the certificate proves nothing about the device (and the private key is thrown
    // away). The correct flow is the "sign" API over a CSR made from the device's own key; until that exists,
    // issuing certificates would only create meaningless ones, and would make approving a device depend on
    // OpenBao PKI being configured. Nothing consumes the certificate yet (device calls authenticate by signing
    // with the enrolled key), so skipping it loses nothing. See OPEN_QUESTIONS OQ-23.
    @Value("\${iam.device.issue-certificates:false}") private val issueCertificates: Boolean,
    // What the platform DOES when an agent reports that its own files were tampered with (spec P1-16, "configurable
    // response"): `report` (default) records it and shows it; `suspend` also suspends an approved device until an
    // administrator reactivates it. Any other value is treated as `report`, so a typo can never lock devices out.
    @Value("\${iam.device.tamper-response:report}") private val tamperResponse: String = "report",
) {
    private val secureRandom = SecureRandom()

    private companion object {
        val TAMPER_EVENTS = setOf("agent.tamper_detected", "device.tampering")
        const val SYSTEM_ACTOR = "system:tamper-response"
    }

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
            if (issueCertificates) {
                val issued = issueCertificateFor(device, keyId)
                certificatePem = issued.certificatePem
                issuingCaPem = issued.issuingCaPem
                certificateStatus = CertificateStatus.ACTIVE.name
            }
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
            message = when {
                approvalMode != ApprovalMode.AUTOMATIC -> "Device registration submitted"
                certificatePem != null -> "Device approved and certificate issued"
                else -> "Device approved"
            },
        )
    }

    // ---- Inventory (Admin Console, Section 13) ----

    fun listDevices(tenantId: UUID): List<DeviceSummaryResponse> =
        deviceRepository.findByTenantId(tenantId).map { toSummary(it) }

    fun getDevice(tenantId: UUID, deviceId: UUID): DeviceSummaryResponse =
        toSummary(requireDevice(tenantId, deviceId))

    /** The device's 50 most recent events, newest first. A device of another tenant looks like "not found". */
    fun listEvents(tenantId: UUID, deviceId: UUID): List<DeviceEventResponse> {
        requireDevice(tenantId, deviceId)
        return eventRepository.findTop50ByDeviceIdOrderByOccurredAtDesc(deviceId)
            .map { DeviceEventResponse(it.eventType, it.severity, it.metadataJson, it.occurredAt) }
    }

    private fun toSummary(device: IamDeviceEntity): DeviceSummaryResponse {
        val posture = postureRepository.findById(device.id).orElse(null)
        val cert = certificateRepository.findByDeviceIdAndStatus(device.id, CertificateStatus.ACTIVE.name)
        // Display only: an unreadable stored document just means "no detail to show", never an error.
        val signals = posture?.signalsJson?.let { runCatching { objectMapper.readValue(it, PostureSignals::class.java) }.getOrNull() }
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
            postureRiskScore = posture?.riskScore,
            postureEvaluatedAt = posture?.evaluatedAt,
            postureReasons = signals?.let { PostureEvaluator.evaluate(it).reasons } ?: emptyList(),
            postureSignals = signals,
            certificateStatus = cert?.status,
            createdAt = device.createdAt,
            identity = identityDetails(device),
        )
    }

    private fun identityDetails(device: IamDeviceEntity): DeviceIdentityDetails {
        val hardware = hardwareRepository.findById(device.id).orElse(null)
        val key = keyRepository.findByDeviceIdAndStatus(device.id, KeyStatus.ACTIVE.name)
        return DeviceIdentityDetails(
            agentInstanceId = device.deviceInstanceId,
            fingerprintVersion = hardware?.fingerprintVersion,
            fingerprintHash = hardware?.fingerprintHash,
            manufacturer = hardware?.manufacturer,
            model = hardware?.model,
            osVersion = hardware?.osVersion,
            keyAlgorithm = key?.keyAlgorithm,
            keyAssuranceLevel = key?.assuranceLevel,
            keyCreatedAt = key?.createdAt,
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
        if (issueCertificates && activeKey != null && certificateRepository.findByDeviceIdAndStatus(deviceId, CertificateStatus.ACTIVE.name) == null) {
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

    /**
     * Soft-delete: removes the device record and all related rows so the agent
     * can re-enroll fresh (new device ID, new PENDING_APPROVAL).
     * Useful for demos and device reassignment.
     */
    @Transactional
    fun deleteDevice(tenantId: UUID, deviceId: UUID, actorId: String, sourceIp: String?) {
        val device = requireDevice(tenantId, deviceId)
        // Revoke certificate first if one is active
        val activeCert = certificateRepository.findByDeviceIdAndStatus(deviceId, CertificateStatus.ACTIVE.name)
        if (activeCert != null) {
            try { pkiClient.revokeCertificate(activeCert.serialNumber) } catch (_: Exception) {}
        }
        // Audit before deletion so the event is queryable after the fact
        audit(tenantId, deviceId, actorId, "device.deleted", AuditResult.SUCCESS, null, sourceIp)
        // Delete all child rows, then the device itself
        certificateRepository.deleteByDeviceId(deviceId)
        approvalRepository.deleteByDeviceId(deviceId)
        eventRepository.deleteByDeviceId(deviceId)
        keyRepository.deleteByDeviceId(deviceId)
        hardwareRepository.deleteByDeviceId(deviceId)
        postureRepository.deleteByDeviceId(deviceId)
        heartbeatRepository.deleteByDeviceId(deviceId)
        deviceRepository.delete(device)
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

    /**
     * The agent reports facts; this decides what they mean (see [PostureEvaluator]). The verdict is always
     * recorded. It only changes the device's lifecycle when posture enforcement is switched on
     * (`iam.device.enforce-posture`), and then reversibly: a non-compliant approved device becomes
     * NON_COMPLIANT, and returns to APPROVED once it reports compliant again.
     */
    @Transactional
    fun updatePosture(tenantId: UUID, deviceId: UUID, request: DevicePostureRequest) {
        val device = requireDevice(tenantId, deviceId)
        val now = Instant.now()
        val evaluation = PostureEvaluator.evaluate(request.signals)
        val signalsJson = objectMapper.writeValueAsString(request.signals)

        val existing = postureRepository.findById(deviceId).orElse(null)
        val previousStatus = existing?.postureStatus
        if (existing != null) {
            existing.postureStatus = evaluation.status.name
            existing.riskScore = evaluation.riskScore
            existing.signalsJson = signalsJson
            existing.evaluatedAt = now
            postureRepository.save(existing)
        } else {
            postureRepository.save(DevicePostureEntity(deviceId, evaluation.status.name, evaluation.riskScore, signalsJson, now))
        }

        // Once per change, not once per report: the agent re-reports every 15 minutes.
        if (evaluation.status == PostureStatus.NON_COMPLIANT && previousStatus != PostureStatus.NON_COMPLIANT.name) {
            publishDeviceEvent(tenantId, deviceId, "device.noncompliant", EventSeverity.WARNING, objectMapper.writeValueAsString(mapOf("reasons" to evaluation.reasons)))
        }
        if (enforcePosture) {
            applyPostureEnforcement(device, evaluation.status, now)
        }
    }

    private fun applyPostureEnforcement(device: IamDeviceEntity, status: PostureStatus, now: Instant) {
        val newLifecycle = when {
            status == PostureStatus.NON_COMPLIANT && device.lifecycleStatus == DeviceLifecycleStatus.APPROVED.name -> DeviceLifecycleStatus.NON_COMPLIANT
            status == PostureStatus.COMPLIANT && device.lifecycleStatus == DeviceLifecycleStatus.NON_COMPLIANT.name -> DeviceLifecycleStatus.APPROVED
            else -> return
        }
        device.lifecycleStatus = newLifecycle.name
        device.updatedAt = now
        deviceRepository.save(device)
        val (event, severity) =
            if (newLifecycle == DeviceLifecycleStatus.APPROVED) "device.posture_restored" to EventSeverity.INFO else "device.posture_enforced" to EventSeverity.WARNING
        publishDeviceEvent(device.tenantId, device.id, event, severity, null)
    }

    @Transactional
    fun recordEvent(tenantId: UUID, deviceId: UUID, request: DeviceEventRequest) {
        val device = requireDevice(tenantId, deviceId)
        publishDeviceEvent(tenantId, deviceId, request.eventType, EventSeverity.valueOf(request.severity), request.metadataJson)
        if (request.eventType in TAMPER_EVENTS) applyTamperResponse(device)
    }

    /**
     * The configured response to tampering. Only an APPROVED device is suspended (a pending, suspended or revoked one
     * already has no trusted access). Never undone automatically when the agent later reports the files restored: an
     * administrator looks first and reactivates.
     */
    private fun applyTamperResponse(device: IamDeviceEntity) {
        if (tamperResponse.trim().lowercase() != "suspend") return
        if (device.lifecycleStatus != DeviceLifecycleStatus.APPROVED.name) return
        device.lifecycleStatus = DeviceLifecycleStatus.SUSPENDED.name
        device.updatedAt = Instant.now()
        deviceRepository.save(device)
        val reason = "agent reported tampering with its own files"
        recordApproval(device.id, ApprovalMode.AUTOMATIC, ApprovalDecision.SUSPENDED, SYSTEM_ACTOR, reason)
        audit(device.tenantId, device.id, SYSTEM_ACTOR, "device.suspended", AuditResult.SUCCESS, reason, null)
    }

    @Transactional
    fun recordCompliance(tenantId: UUID, deviceId: UUID, request: DeviceComplianceRequest) {
        updatePosture(tenantId, deviceId, DevicePostureRequest(request.signals))
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
        // The repository returns rows in no defined order; the signed order must be deterministic.
        val apps = DevicePolicyCanonical.ordered(
            policyEntity?.let { appPolicyRepository.findByPolicyId(it.id) }?.map {
                DeviceAppPolicyResponse(it.applicationId, it.pendingAccess, it.offlineAccess, it.offlineGraceSeconds, it.failureMode)
            } ?: emptyList(),
        )

        // Whole seconds, so the JSON the agent receives and the epoch seconds that were signed can
        // never disagree about the instant (no sub-second part to truncate differently on each side).
        val now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
        val expiresAt = now.plusSeconds(DEFAULT_POLICY.heartbeatIntervalSeconds.toLong() * 3)
        val canonical = DevicePolicyCanonical.encode(
            tenantId = tenantId,
            deviceId = deviceId,
            policyId = policyId,
            policyVersion = policyVersion,
            issuedAt = now,
            expiresAt = expiresAt,
            deviceStatus = device.lifecycleStatus,
            heartbeatIntervalSeconds = DEFAULT_POLICY.heartbeatIntervalSeconds,
            postureIntervalSeconds = DEFAULT_POLICY.postureIntervalSeconds,
            agentFailureMode = DEFAULT_POLICY.agentFailureMode.name,
            apps = apps,
        )
        val signature = transitClient.sign("device-policy", canonical.toByteArray(Charsets.UTF_8))

        return DevicePolicyResponse(
            tenantId = tenantId,
            deviceId = deviceId,
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

    private fun requireDevice(tenantId: UUID, deviceId: UUID): IamDeviceEntity {
        val device = deviceRepository.findById(deviceId).orElse(null) ?: throw DeviceNotFoundException(deviceId)
        if (device.tenantId != tenantId) throw DeviceNotFoundException(deviceId) // cross-tenant lookup must look identical to "not found" (Section 16)
        return device
    }

    private fun audit(tenantId: UUID, deviceId: UUID, actorId: String, action: String, result: AuditResult, reason: String?, sourceIp: String?) {
        eventRepository.save(
            DeviceEventEntity(
                id = UUID.randomUUID(),
                tenantId = tenantId,
                deviceId = deviceId,
                eventType = action,
                severity = if (action == "device.revoked" || action == "device.suspended") EventSeverity.WARNING.name else EventSeverity.INFO.name,
                metadataJson = objectMapper.writeValueAsString(mapOf("actor" to actorId, "reason" to reason)),
            ),
        )
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
