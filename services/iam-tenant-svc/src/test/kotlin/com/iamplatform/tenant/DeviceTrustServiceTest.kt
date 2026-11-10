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
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.security.KeyPairGenerator
import java.security.Signature
import java.time.Instant
import java.util.Base64
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

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

    private val service = DeviceTrustService(
        deviceRepository, hardwareRepository, keyRepository, certificateRepository, approvalRepository,
        postureRepository, heartbeatRepository, eventRepository, policyRepository, appPolicyRepository,
        enrollmentTransactionRepository, DeviceSignatureVerifier(), pkiClient, transitClient, auditPublisher,
    )

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

        val response = service.completeEnrollment(request, "1.2.3.4")

        assertEquals(DeviceLifecycleStatus.APPROVED.name, response.status)
        assertEquals(ApprovalMode.AUTOMATIC.name, response.approvalType)
        assertEquals("cert-pem", response.certificatePem)
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
}
