package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.vault.IssuedCertificate
import com.iamplatform.servicekit.vault.OpenBaoPkiClient
import com.iamplatform.servicekit.vault.OpenBaoTransitClient
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.argThat
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import tools.jackson.module.kotlin.jacksonObjectMapper
import java.security.KeyPairGenerator
import java.security.Signature
import java.time.Instant
import java.util.Base64
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Uses a real Ed25519 key pair and the real DeviceSignatureVerifier (not
 * mocked) so proof-of-possession and device-authenticated-request checks
 * are genuinely exercised, not assumed -- the whole point of these checks
 * is that they reject a bad signature, which a mocked verifier can't prove.
 */
class DeviceTrustServiceTest {

    private val deviceRepository = mock<IamDeviceRepository>()
    private val hardwareRepository = mock<DeviceHardwareRepository>()
    private val keyRepository = mock<DeviceKeyRepository>()
    private val certificateRepository = mock<DeviceCertificateRepository>()
    private val approvalRepository = mock<DeviceApprovalRepository>()
    private val postureRepository = mock<DevicePostureRepository>()
    private val heartbeatRepository = mock<DeviceHeartbeatRepository>()
    private val eventRepository = mock<DeviceEventRepository>()
    private val policyRepository = mock<DevicePolicyRepository>()
    private val appPolicyRepository = mock<DeviceAppPolicyRepository>()
    private val enrollmentTransactionRepository = mock<DeviceEnrollmentTransactionRepository>()
    private val pkiClient = mock<OpenBaoPkiClient>()
    private val transitClient = mock<OpenBaoTransitClient>()
    private val auditPublisher = mock<AuditPublisher>()

    private fun newService(enforcePosture: Boolean = false, issueCertificates: Boolean = false, tamperResponse: String = "report") = DeviceTrustService(
        deviceRepository, hardwareRepository, keyRepository, certificateRepository, approvalRepository,
        postureRepository, heartbeatRepository, eventRepository, policyRepository, appPolicyRepository,
        enrollmentTransactionRepository, DeviceSignatureVerifier(), pkiClient, transitClient, auditPublisher,
        jacksonObjectMapper(), enforcePosture, issueCertificates, tamperResponse,
    )

    private val service = newService()

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private lateinit var keyPair: java.security.KeyPair

    @BeforeEach
    fun setUp() {
        keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        whenever(deviceRepository.save(any())).thenAnswer { it.arguments[0] }
        whenever(hardwareRepository.save(any())).thenAnswer { it.arguments[0] }
        whenever(keyRepository.save(any())).thenAnswer { it.arguments[0] }
        whenever(certificateRepository.save(any())).thenAnswer { it.arguments[0] }
        whenever(approvalRepository.save(any())).thenAnswer { it.arguments[0] }
        whenever(eventRepository.save(any())).thenAnswer { it.arguments[0] }
        whenever(enrollmentTransactionRepository.save(any())).thenAnswer { it.arguments[0] }
    }

    private fun sign(data: ByteArray): String =
        Base64.getEncoder().encodeToString(
            Signature.getInstance("Ed25519").apply {
                initSign(keyPair.private)
                update(data)
            }.sign(),
        )

    private fun publicKeyBase64(): String = Base64.getEncoder().encodeToString(keyPair.public.encoded)

    private fun enrollmentRequest(nonce: String, ownership: String = "CORPORATE") = EnrollmentCompleteRequest(
        enrollmentTransactionId = UUID.randomUUID(),
        deviceInstanceId = UUID.randomUUID(),
        platform = "WINDOWS",
        ownership = ownership,
        agentVersion = "1.0.0",
        publicKey = publicKeyBase64(),
        keyAlgorithm = "ED25519",
        assuranceLevel = "SOFTWARE",
        proofOfPossession = sign(nonce.toByteArray(Charsets.UTF_8)),
        fingerprintHash = "fp-hash",
    )

    // Bound to this test's own key pair by default, exactly as /enrollment/start would bind it.
    private fun pendingTransaction(
        nonce: String,
        expiresAt: Instant = Instant.now().plusSeconds(60),
        keyThumbprint: String? = DeviceKeyThumbprint.of(keyPair.public.encoded),
    ) = DeviceEnrollmentTransactionEntity(UUID.randomUUID(), tenantId, userId, nonce, Instant.now(), expiresAt, keyThumbprint = keyThumbprint)

    @Test
    fun `completeEnrollment auto-approves a corporate device and issues a certificate`() {
        val nonce = "challenge-nonce"
        val tx = pendingTransaction(nonce)
        val request = enrollmentRequest(nonce)
        whenever(enrollmentTransactionRepository.findById(request.enrollmentTransactionId)).thenReturn(Optional.of(tx))
        whenever(deviceRepository.countByTenantIdAndUserIdAndLifecycleStatusNotIn(any(), any(), any())).thenReturn(0)
        whenever(pkiClient.issueCertificate(any(), any(), any(), any(), any())).thenReturn(
            IssuedCertificate("cert-pem", "ca-pem", "serial-1", Instant.now(), Instant.now().plusSeconds(3600)),
        )

        val response = newService(issueCertificates = true).completeEnrollment(request, "1.2.3.4")

        assertEquals(DeviceLifecycleStatus.APPROVED.name, response.status)
        assertEquals(ApprovalMode.AUTOMATIC.name, response.approvalType)
        assertEquals("cert-pem", response.certificatePem)
        assertEquals("Device approved and certificate issued", response.message)
        verify(pkiClient).issueCertificate(any(), any(), any(), any(), any())
    }

    @Test
    fun `by default a corporate device is approved without touching OpenBao PKI`() {
        val nonce = "challenge-nonce"
        val tx = pendingTransaction(nonce)
        val request = enrollmentRequest(nonce)
        whenever(enrollmentTransactionRepository.findById(request.enrollmentTransactionId)).thenReturn(Optional.of(tx))
        whenever(deviceRepository.countByTenantIdAndUserIdAndLifecycleStatusNotIn(any(), any(), any())).thenReturn(0)

        val response = service.completeEnrollment(request, "1.2.3.4")

        assertEquals(DeviceLifecycleStatus.APPROVED.name, response.status)
        assertEquals("NOT_ISSUED", response.certificateStatus)
        assertNull(response.certificatePem)
        assertEquals("Device approved", response.message)
        verify(pkiClient, never()).issueCertificate(any(), any(), any(), any(), any())
    }

    @Test
    fun `an admin approving a pending device works with no PKI, and issues a certificate only when enabled`() {
        val device = approvedDevice(status = DeviceLifecycleStatus.PENDING_APPROVAL.name)
        val key = DeviceKeyEntity(UUID.randomUUID(), device.id, publicKeyBase64(), "ED25519", "SOFTWARE", KeyStatus.ACTIVE.name)
        whenever(keyRepository.findByDeviceIdAndStatus(device.id, KeyStatus.ACTIVE.name)).thenReturn(key)

        service.approve(tenantId, device.id, "admin-1", null, "1.2.3.4")
        assertEquals(DeviceLifecycleStatus.APPROVED.name, device.lifecycleStatus)
        verify(pkiClient, never()).issueCertificate(any(), any(), any(), any(), any())

        whenever(pkiClient.issueCertificate(any(), any(), any(), any(), any())).thenReturn(
            IssuedCertificate("cert-pem", "ca-pem", "serial-2", Instant.now(), Instant.now().plusSeconds(3600)),
        )
        device.lifecycleStatus = DeviceLifecycleStatus.PENDING_APPROVAL.name
        newService(issueCertificates = true).approve(tenantId, device.id, "admin-1", null, "1.2.3.4")
        verify(pkiClient).issueCertificate(any(), any(), any(), any(), any())
    }

    @Test
    fun `completeEnrollment leaves a BYOD device pending manual approval`() {
        val nonce = "challenge-nonce"
        val tx = pendingTransaction(nonce)
        val request = enrollmentRequest(nonce, ownership = "BYOD")
        whenever(enrollmentTransactionRepository.findById(request.enrollmentTransactionId)).thenReturn(Optional.of(tx))
        whenever(deviceRepository.countByTenantIdAndUserIdAndLifecycleStatusNotIn(any(), any(), any())).thenReturn(0)

        val response = service.completeEnrollment(request, "1.2.3.4")

        assertEquals(DeviceLifecycleStatus.PENDING_APPROVAL.name, response.status)
        assertEquals(ApprovalMode.MANUAL.name, response.approvalType)
        assertNull(response.certificatePem)
        verify(pkiClient, never()).issueCertificate(any(), any(), any(), any(), any())
    }

    @Test
    fun `completeEnrollment rejects a forged proof-of-possession signature`() {
        val nonce = "challenge-nonce"
        val tx = pendingTransaction(nonce)
        val otherKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val forgedSignature = Base64.getEncoder().encodeToString(
            Signature.getInstance("Ed25519").apply {
                initSign(otherKeyPair.private) // signed with the WRONG key
                update(nonce.toByteArray(Charsets.UTF_8))
            }.sign(),
        )
        val request = enrollmentRequest(nonce).copy(proofOfPossession = forgedSignature)
        whenever(enrollmentTransactionRepository.findById(request.enrollmentTransactionId)).thenReturn(Optional.of(tx))

        assertThrows<DeviceProofOfPossessionException> { service.completeEnrollment(request, "1.2.3.4") }
        verify(deviceRepository, never()).save(any())
        assertNotNull(tx.consumedAt) // a failed attempt burns the transaction, no retries
    }

    @Test
    fun `completeEnrollment rejects a validly-signed request from a key other than the one the transaction is bound to`() {
        // An attacker who intercepted the transaction id + nonce off the loopback redirect, and signs
        // with their own key -- the signature itself is perfectly valid, only the key binding stops it.
        val nonce = "challenge-nonce"
        val tx = pendingTransaction(nonce)
        val attackerKeyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val attackerSignature = Base64.getEncoder().encodeToString(
            Signature.getInstance("Ed25519").apply {
                initSign(attackerKeyPair.private)
                update(nonce.toByteArray(Charsets.UTF_8))
            }.sign(),
        )
        val request = enrollmentRequest(nonce).copy(
            publicKey = Base64.getEncoder().encodeToString(attackerKeyPair.public.encoded),
            proofOfPossession = attackerSignature,
        )
        whenever(enrollmentTransactionRepository.findById(request.enrollmentTransactionId)).thenReturn(Optional.of(tx))

        val ex = assertThrows<DeviceProofOfPossessionException> { service.completeEnrollment(request, "1.2.3.4") }
        assertEquals("Public key does not match the key this enrollment was started for", ex.message)
        verify(deviceRepository, never()).save(any())
        assertNotNull(tx.consumedAt)
    }

    @Test
    fun `completeEnrollment rejects a transaction that was never bound to a key`() {
        val nonce = "challenge-nonce"
        val tx = pendingTransaction(nonce, keyThumbprint = null)
        val request = enrollmentRequest(nonce)
        whenever(enrollmentTransactionRepository.findById(request.enrollmentTransactionId)).thenReturn(Optional.of(tx))

        assertThrows<EnrollmentTransactionInvalidException> { service.completeEnrollment(request, "1.2.3.4") }
        verify(deviceRepository, never()).save(any())
    }

    @Test
    fun `key thumbprint matches the pinned cross-language test vector`() {
        // SHA-256("abc"), base64url without padding -- the Rust agent's key_provider test pins the
        // identical value, so the two implementations can't silently drift apart.
        assertEquals("ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0", DeviceKeyThumbprint.of("abc".toByteArray(Charsets.US_ASCII)))
    }

    @Test
    fun `startEnrollment binds the new transaction to the given key thumbprint`() {
        val thumbprint = DeviceKeyThumbprint.of(keyPair.public.encoded)

        service.startEnrollment(tenantId, userId, thumbprint)

        verify(enrollmentTransactionRepository).save(argThat<DeviceEnrollmentTransactionEntity> { this.keyThumbprint == thumbprint })
    }

    @Test
    fun `completeEnrollment rejects an expired transaction`() {
        val nonce = "challenge-nonce"
        val tx = pendingTransaction(nonce, expiresAt = Instant.now().minusSeconds(10))
        val request = enrollmentRequest(nonce)
        whenever(enrollmentTransactionRepository.findById(request.enrollmentTransactionId)).thenReturn(Optional.of(tx))

        assertThrows<EnrollmentTransactionInvalidException> { service.completeEnrollment(request, "1.2.3.4") }
    }

    @Test
    fun `completeEnrollment rejects a transaction that was already consumed`() {
        val nonce = "challenge-nonce"
        val tx = pendingTransaction(nonce).also { it.consumedAt = Instant.now() }
        val request = enrollmentRequest(nonce)
        whenever(enrollmentTransactionRepository.findById(request.enrollmentTransactionId)).thenReturn(Optional.of(tx))

        assertThrows<EnrollmentTransactionInvalidException> { service.completeEnrollment(request, "1.2.3.4") }
    }

    @Test
    fun `completeEnrollment enforces the per-user device limit`() {
        val nonce = "challenge-nonce"
        val tx = pendingTransaction(nonce)
        val request = enrollmentRequest(nonce)
        whenever(enrollmentTransactionRepository.findById(request.enrollmentTransactionId)).thenReturn(Optional.of(tx))
        whenever(deviceRepository.countByTenantIdAndUserIdAndLifecycleStatusNotIn(any(), any(), any())).thenReturn(5)

        assertThrows<DeviceLimitExceededException> { service.completeEnrollment(request, "1.2.3.4") }
        verify(deviceRepository, never()).save(any())
    }

    @Test
    fun `revoke revokes the active certificate in OpenBao and marks it revoked locally`() {
        val deviceId = UUID.randomUUID()
        val device = IamDeviceEntity(deviceId, tenantId, userId, UUID.randomUUID(), ownership = "CORPORATE", lifecycleStatus = DeviceLifecycleStatus.APPROVED.name)
        val cert = DeviceCertificateEntity(UUID.randomUUID(), deviceId, UUID.randomUUID(), "endpoint-device", "serial-1", "serial-1", Instant.now(), Instant.now().plusSeconds(3600))
        whenever(deviceRepository.findById(deviceId)).thenReturn(Optional.of(device))
        whenever(certificateRepository.findByDeviceIdAndStatus(deviceId, CertificateStatus.ACTIVE.name)).thenReturn(cert)

        service.revoke(tenantId, deviceId, "admin-1", "lost device", "1.2.3.4")

        assertEquals(DeviceLifecycleStatus.REVOKED.name, device.lifecycleStatus)
        verify(pkiClient).revokeCertificate("serial-1")
        assertEquals(CertificateStatus.REVOKED.name, cert.status)
        verify(auditPublisher).publish(argThat<AuditEvent> { this.action == "device.revoked" && this.deviceId == device.id.toString() })
    }

    @Test
    fun `revoke rejects a device belonging to a different tenant`() {
        val deviceId = UUID.randomUUID()
        val device = IamDeviceEntity(deviceId, UUID.randomUUID(), userId, UUID.randomUUID(), ownership = "CORPORATE", lifecycleStatus = DeviceLifecycleStatus.APPROVED.name)
        whenever(deviceRepository.findById(deviceId)).thenReturn(Optional.of(device))

        assertThrows<DeviceNotFoundException> { service.revoke(tenantId, deviceId, "admin-1", null, "1.2.3.4") }
    }

    @Test
    fun `fetchPolicy signs exactly the canonical form of the response it returns, bound to this device and tenant`() {
        val deviceId = UUID.randomUUID()
        val device = IamDeviceEntity(deviceId, tenantId, userId, UUID.randomUUID(), ownership = "CORPORATE", lifecycleStatus = "APPROVED")
        whenever(deviceRepository.findById(deviceId)).thenReturn(Optional.of(device))
        whenever(policyRepository.findTopByTenantIdOrderByVersionDesc(tenantId)).thenReturn(null)
        whenever(transitClient.sign(any(), any())).thenReturn("vault:v1:test-signature")

        val response = service.fetchPolicy(tenantId, deviceId)

        val signedBytes = argumentCaptor<ByteArray>()
        verify(transitClient).sign(eq("device-policy"), signedBytes.capture())
        val expected = DevicePolicyCanonical.encode(
            tenantId, deviceId, response.policyId, response.policyVersion, response.issuedAt, response.expiresAt,
            response.deviceStatus, response.heartbeatIntervalSeconds, response.postureIntervalSeconds,
            response.agentFailureMode, response.applications,
        )
        assertEquals(expected, String(signedBytes.firstValue, Charsets.UTF_8))
        assertEquals(tenantId, response.tenantId)
        assertEquals(deviceId, response.deviceId)
        assertEquals("vault:v1:test-signature", response.signature)
        assertEquals(0, response.issuedAt.nano) // whole seconds: nothing for the two sides to truncate differently
    }

    @Test
    fun `fetchPolicy refuses a device that belongs to another tenant`() {
        val deviceId = UUID.randomUUID()
        val device = IamDeviceEntity(deviceId, UUID.randomUUID(), userId, UUID.randomUUID(), ownership = "CORPORATE", lifecycleStatus = "APPROVED")
        whenever(deviceRepository.findById(deviceId)).thenReturn(Optional.of(device))

        assertThrows<DeviceNotFoundException> { service.fetchPolicy(tenantId, deviceId) }
        verify(transitClient, never()).sign(any(), any())
    }

    @Test
    fun `requireDeviceProof accepts a valid fresh signature and rejects a stale one`() {
        val deviceId = UUID.randomUUID()
        val device = IamDeviceEntity(deviceId, tenantId, userId, UUID.randomUUID(), ownership = "CORPORATE", lifecycleStatus = DeviceLifecycleStatus.APPROVED.name)
        val key = DeviceKeyEntity(UUID.randomUUID(), deviceId, publicKeyBase64(), "ED25519", "SOFTWARE", KeyStatus.ACTIVE.name)
        whenever(deviceRepository.findById(deviceId)).thenReturn(Optional.of(device))
        whenever(keyRepository.findByDeviceIdAndStatus(deviceId, KeyStatus.ACTIVE.name)).thenReturn(key)

        val freshTimestamp = Instant.now()
        val validSignature = sign("$deviceId:$freshTimestamp".toByteArray(Charsets.UTF_8))
        val result = service.requireDeviceProof(tenantId, deviceId, freshTimestamp, validSignature)
        assertNotNull(result)

        val staleTimestamp = Instant.now().minusSeconds(600)
        val staleSignature = sign("$deviceId:$staleTimestamp".toByteArray(Charsets.UTF_8))
        assertThrows<DeviceProofOfPossessionException> { service.requireDeviceProof(tenantId, deviceId, staleTimestamp, staleSignature) }
    }

    // ---- posture (server decides; enforcement is opt-in) ----

    private fun approvedDevice(deviceId: UUID = UUID.randomUUID(), status: String = DeviceLifecycleStatus.APPROVED.name): IamDeviceEntity {
        val device = IamDeviceEntity(deviceId, tenantId, userId, UUID.randomUUID(), ownership = "CORPORATE", lifecycleStatus = status)
        whenever(deviceRepository.findById(deviceId)).thenReturn(Optional.of(device))
        whenever(postureRepository.save(any())).thenAnswer { it.arguments[0] }
        return device
    }

    private val failing = PostureSignals(diskEncryption = "DISABLED", antivirus = "ENABLED", firewall = "ENABLED")
    private val passing = PostureSignals(diskEncryption = "ENABLED", antivirus = "ENABLED", firewall = "ENABLED")

    @Test
    fun `a failing posture report is recorded but does not touch the device while enforcement is off`() {
        val device = approvedDevice()
        whenever(postureRepository.findById(device.id)).thenReturn(Optional.empty())

        service.updatePosture(tenantId, device.id, DevicePostureRequest(failing))

        assertEquals(DeviceLifecycleStatus.APPROVED.name, device.lifecycleStatus) // the safety property
        val saved = argumentCaptor<DevicePostureEntity>()
        verify(postureRepository).save(saved.capture())
        assertEquals(PostureStatus.NON_COMPLIANT.name, saved.firstValue.postureStatus)
        assertEquals(40, saved.firstValue.riskScore)
        assertTrue(saved.firstValue.signalsJson!!.contains("\"diskEncryption\":\"DISABLED\""))
    }

    @Test
    fun `with enforcement on, a failing report suspends an approved device and a passing one restores it`() {
        val enforcing = newService(enforcePosture = true)
        val device = approvedDevice()
        whenever(postureRepository.findById(device.id)).thenReturn(Optional.empty())

        enforcing.updatePosture(tenantId, device.id, DevicePostureRequest(failing))
        assertEquals(DeviceLifecycleStatus.NON_COMPLIANT.name, device.lifecycleStatus)

        enforcing.updatePosture(tenantId, device.id, DevicePostureRequest(passing))
        assertEquals(DeviceLifecycleStatus.APPROVED.name, device.lifecycleStatus)
    }

    @Test
    fun `enforcement never promotes a device that is not approved, whatever its posture`() {
        val enforcing = newService(enforcePosture = true)
        for (status in listOf(DeviceLifecycleStatus.PENDING_APPROVAL, DeviceLifecycleStatus.SUSPENDED, DeviceLifecycleStatus.REVOKED, DeviceLifecycleStatus.REJECTED)) {
            val device = approvedDevice(status = status.name)
            whenever(postureRepository.findById(device.id)).thenReturn(Optional.empty())
            enforcing.updatePosture(tenantId, device.id, DevicePostureRequest(passing))
            assertEquals(status.name, device.lifecycleStatus, "a compliant report must never approve a $status device")
        }
    }

    @Test
    fun `the non-compliant event fires when the status changes, not on every repeat report`() {
        val device = approvedDevice()
        val already = DevicePostureEntity(device.id, PostureStatus.NON_COMPLIANT.name, 40, "{}", Instant.now())
        whenever(postureRepository.findById(device.id)).thenReturn(Optional.of(already))

        service.updatePosture(tenantId, device.id, DevicePostureRequest(failing))
        verify(eventRepository, never()).save(any())

        val wasFine = DevicePostureEntity(device.id, PostureStatus.COMPLIANT.name, 0, "{}", Instant.now())
        whenever(postureRepository.findById(device.id)).thenReturn(Optional.of(wasFine))
        service.updatePosture(tenantId, device.id, DevicePostureRequest(failing))
        verify(eventRepository).save(argThat<DeviceEventEntity> { eventType == "device.noncompliant" && severity == "WARNING" })
    }

    @Test
    fun `the device summary carries the signals and the plain-language reasons`() {
        val device = approvedDevice()
        val stored = jacksonObjectMapper().writeValueAsString(failing)
        whenever(postureRepository.findById(device.id)).thenReturn(Optional.of(DevicePostureEntity(device.id, "NON_COMPLIANT", 40, stored, Instant.now())))

        val summary = service.getDevice(tenantId, device.id)

        assertEquals("NON_COMPLIANT", summary.postureStatus)
        assertEquals(40, summary.postureRiskScore)
        assertEquals(listOf("Disk encryption (BitLocker) is off"), summary.postureReasons)
        assertEquals("DISABLED", summary.postureSignals?.diskEncryption)
    }

    @Test
    fun `a corrupt stored signals document degrades to no detail instead of failing the whole device list`() {
        val device = approvedDevice()
        whenever(postureRepository.findById(device.id)).thenReturn(Optional.of(DevicePostureEntity(device.id, "UNKNOWN", 30, "{ not json", Instant.now())))

        val summary = service.getDevice(tenantId, device.id)

        assertEquals("UNKNOWN", summary.postureStatus)
        assertEquals(null, summary.postureSignals)
        assertTrue(summary.postureReasons.isEmpty())
    }

    @Test
    fun `a posture report for another tenant's device is refused`() {
        val deviceId = UUID.randomUUID()
        whenever(deviceRepository.findById(deviceId)).thenReturn(Optional.of(IamDeviceEntity(deviceId, UUID.randomUUID(), userId, UUID.randomUUID(), ownership = "CORPORATE", lifecycleStatus = "APPROVED")))
        assertThrows<DeviceNotFoundException> { service.updatePosture(tenantId, deviceId, DevicePostureRequest(passing)) }
        verify(postureRepository, never()).save(any())
    }

    @Test
    fun `the activity timeline returns the device's events newest first`() {
        val service = newService()
        val device = approvedDevice()
        whenever(deviceRepository.findById(device.id)).thenReturn(Optional.of(device))
        val newer = DeviceEventEntity(UUID.randomUUID(), tenantId, device.id, "device.tampering", "CRITICAL", null, Instant.parse("2026-11-17T10:00:00Z"))
        val older = DeviceEventEntity(UUID.randomUUID(), tenantId, device.id, "device.enrollment.submitted", "INFO", null, Instant.parse("2026-11-16T10:00:00Z"))
        whenever(eventRepository.findTop50ByDeviceIdOrderByOccurredAtDesc(device.id)).thenReturn(listOf(newer, older))

        val events = service.listEvents(tenantId, device.id)

        assertEquals(listOf("device.tampering", "device.enrollment.submitted"), events.map { it.eventType })
        assertEquals("CRITICAL", events.first().severity)
    }

    @Test
    fun `the activity timeline of another tenant's device looks like not found`() {
        val service = newService()
        val device = approvedDevice()
        whenever(deviceRepository.findById(device.id)).thenReturn(Optional.of(device))
        assertThrows<DeviceNotFoundException> { service.listEvents(UUID.randomUUID(), device.id) }
        verify(eventRepository, never()).findTop50ByDeviceIdOrderByOccurredAtDesc(any())
    }

    @Test
    fun `an admin action is put on the device's own timeline as well as the audit log`() {
        val service = newService()
        val device = approvedDevice(status = DeviceLifecycleStatus.PENDING_APPROVAL.name)
        whenever(deviceRepository.findById(device.id)).thenReturn(Optional.of(device))
        whenever(deviceRepository.save(any<IamDeviceEntity>())).thenAnswer { it.arguments[0] }

        service.suspend(tenantId, device.id, "admin-1", "lost laptop", "1.2.3.4")

        verify(eventRepository).save(argThat<DeviceEventEntity> { eventType == "device.suspended" && severity == "WARNING" && metadataJson!!.contains("admin-1") })
    }

    // ---- P1-16 configurable tamper response ----

    private fun tamper(service: DeviceTrustService, device: IamDeviceEntity, type: String = "agent.tamper_detected") =
        service.recordEvent(tenantId, device.id, DeviceEventRequest(type, "CRITICAL", null))

    @Test
    fun `by default a tamper report is recorded but the device is not touched`() {
        val device = approvedDevice()
        tamper(newService(), device)
        assertEquals(DeviceLifecycleStatus.APPROVED.name, device.lifecycleStatus)
        verify(deviceRepository, never()).save(any<IamDeviceEntity>())
        verify(eventRepository).save(argThat<DeviceEventEntity> { eventType == "agent.tamper_detected" })
    }

    @Test
    fun `with the suspend response a tamper report suspends an approved device and says who did it`() {
        whenever(deviceRepository.save(any<IamDeviceEntity>())).thenAnswer { it.arguments[0] }
        val device = approvedDevice()
        tamper(newService(tamperResponse = "suspend"), device)
        assertEquals(DeviceLifecycleStatus.SUSPENDED.name, device.lifecycleStatus)
        verify(approvalRepository).save(argThat<DeviceApprovalEntity> { decision == "SUSPENDED" && approvalMode == "AUTOMATIC" && actorId == "system:tamper-response" })
    }

    @Test
    fun `the suspend response never touches a device that is not approved`() {
        for (status in listOf("PENDING_APPROVAL", "SUSPENDED", "REVOKED", "REJECTED")) {
            val device = approvedDevice(status = status)
            tamper(newService(tamperResponse = "suspend"), device)
            assertEquals(status, device.lifecycleStatus, status)
        }
        verify(deviceRepository, never()).save(any<IamDeviceEntity>())
    }

    @Test
    fun `a tamper-cleared report or any other event does not suspend, and a typo in the setting means report only`() {
        val a = approvedDevice()
        tamper(newService(tamperResponse = "suspend"), a, type = "agent.tamper_cleared")
        assertEquals(DeviceLifecycleStatus.APPROVED.name, a.lifecycleStatus)
        val b = approvedDevice()
        tamper(newService(tamperResponse = "suspnd"), b)
        assertEquals(DeviceLifecycleStatus.APPROVED.name, b.lifecycleStatus)
        verify(deviceRepository, never()).save(any<IamDeviceEntity>())
    }
}
