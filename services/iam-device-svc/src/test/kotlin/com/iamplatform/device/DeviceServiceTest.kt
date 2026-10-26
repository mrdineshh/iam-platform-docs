package com.iamplatform.device

import com.iamplatform.device.client.IdentityClient
import com.iamplatform.device.client.RemoteUser
import com.iamplatform.device.crypto.EncryptedSecret
import com.iamplatform.device.crypto.TotpCryptoService
import com.iamplatform.device.crypto.TotpGenerator
import com.iamplatform.device.fcm.FcmClient
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeviceServiceTest {

    private val repository = mock<DeviceRepository>()
    private val identityClient = mock<IdentityClient>()
    private val totpCrypto = mock<TotpCryptoService>()
    private val fcmClient = mock<FcmClient>()
    private val pushChallengeService = mock<PushChallengeService>()
    private val auditPublisher = mock<AuditPublisher>()
    private val totpPolicy = TotpPolicyProperties()
    private val pushPolicy = PushPolicyProperties(waitTimeoutSeconds = 1)

    private val service = DeviceService(
        repository, identityClient, totpCrypto, fcmClient, pushChallengeService, auditPublisher, totpPolicy, pushPolicy,
    )

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val secret = ByteArray(20) { it.toByte() }

    private fun deviceEntity(status: DeviceStatus = DeviceStatus.ACTIVE, failedAttempts: Int = 0, lockedUntil: Instant? = null) =
        DeviceEntity(
            id = UUID.randomUUID(),
            tenantId = tenantId,
            userId = userId,
            status = status,
            totpSecretCiphertext = ByteArray(1),
            totpSecretNonce = ByteArray(1),
            fcmToken = "fcm-token",
            failedTotpAttempts = failedAttempts,
            lockedUntil = lockedUntil,
        )

    @Test
    fun `enroll rejects a user that does not exist under the given tenant`() {
        whenever(identityClient.findUser(userId)).thenReturn(null)

        assertThrows<UserNotFoundException> {
            service.enroll(EnrollDeviceRequest(tenantId, userId))
        }
        org.mockito.kotlin.verify(repository, org.mockito.kotlin.never()).save(any())
    }

    @Test
    fun `enroll rejects a user that belongs to a different tenant`() {
        whenever(identityClient.findUser(userId)).thenReturn(RemoteUser(userId, UUID.randomUUID()))

        assertThrows<UserNotFoundException> {
            service.enroll(EnrollDeviceRequest(tenantId, userId))
        }
    }

    @Test
    fun `enroll creates a PENDING device and returns the raw secret exactly once`() {
        whenever(identityClient.findUser(userId)).thenReturn(RemoteUser(userId, tenantId))
        whenever(totpCrypto.encrypt(eq(tenantId), any())).thenReturn(EncryptedSecret(ByteArray(1), ByteArray(1)))
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.enroll(EnrollDeviceRequest(tenantId, userId))

        assertEquals(DeviceStatus.PENDING, result.status)
        assertTrue(result.provisioningUri.startsWith("otpauth://totp/"))
        org.mockito.kotlin.verify(auditPublisher).publish(any<AuditEvent>())
    }

    @Test
    fun `verifyTotp activates a PENDING device on the first correct code`() {
        val device = deviceEntity(status = DeviceStatus.PENDING)
        whenever(repository.findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(tenantId, userId)).thenReturn(device)
        whenever(totpCrypto.decrypt(eq(tenantId), any(), any())).thenReturn(secret)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }
        val code = TotpGenerator.generateCode(secret, Instant.now(), totpPolicy.stepSeconds, totpPolicy.digits)

        val result = service.verifyTotp(TotpVerifyRequest(tenantId, userId, code))

        assertTrue(result.valid)
        assertEquals(DeviceStatus2.ACTIVE, result.status)
        assertEquals(DeviceStatus.ACTIVE, device.status)
    }

    @Test
    fun `verifyTotp rejects a wrong code and increments the failure counter`() {
        val device = deviceEntity(failedAttempts = 0)
        whenever(repository.findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(tenantId, userId)).thenReturn(device)
        whenever(totpCrypto.decrypt(eq(tenantId), any(), any())).thenReturn(secret)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }
        val correct = TotpGenerator.generateCode(secret, Instant.now(), totpPolicy.stepSeconds, totpPolicy.digits)
        val wrong = ((correct.toInt() + 1) % 1_000_000).toString().padStart(6, '0')

        val result = service.verifyTotp(TotpVerifyRequest(tenantId, userId, wrong))

        assertFalse(result.valid)
        assertEquals(1, device.failedTotpAttempts)
    }

    @Test
    fun `verifyTotp locks the device after maxFailedAttempts wrong codes`() {
        val device = deviceEntity(failedAttempts = totpPolicy.maxFailedAttempts - 1)
        whenever(repository.findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(tenantId, userId)).thenReturn(device)
        whenever(totpCrypto.decrypt(eq(tenantId), any(), any())).thenReturn(secret)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }
        val correct = TotpGenerator.generateCode(secret, Instant.now(), totpPolicy.stepSeconds, totpPolicy.digits)
        val wrong = ((correct.toInt() + 1) % 1_000_000).toString().padStart(6, '0')

        val result = service.verifyTotp(TotpVerifyRequest(tenantId, userId, wrong))

        assertFalse(result.valid)
        assertEquals(DeviceStatus2.LOCKED, result.status)
        assertTrue(device.lockedUntil!!.isAfter(Instant.now()))
    }

    @Test
    fun `verifyTotp on an already-locked device refuses without checking the code`() {
        val device = deviceEntity(lockedUntil = Instant.now().plusSeconds(300))
        whenever(repository.findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(tenantId, userId)).thenReturn(device)

        val result = service.verifyTotp(TotpVerifyRequest(tenantId, userId, "000000"))

        assertFalse(result.valid)
        assertEquals(DeviceStatus2.LOCKED, result.status)
        org.mockito.kotlin.verify(totpCrypto, org.mockito.kotlin.never()).decrypt(any(), any(), any())
    }

    @Test
    fun `verifyTotp throws when no device is enrolled`() {
        whenever(repository.findFirstByTenantIdAndUserIdOrderByCreatedAtDesc(tenantId, userId)).thenReturn(null)

        assertThrows<DeviceNotFoundException> {
            service.verifyTotp(TotpVerifyRequest(tenantId, userId, "123456"))
        }
    }

    @Test
    fun `sendPush throws when no push-capable device is enrolled`() {
        whenever(repository.findFirstByTenantIdAndUserIdAndFcmTokenIsNotNullOrderByCreatedAtDesc(tenantId, userId)).thenReturn(null)

        assertThrows<NoPushCapableDeviceException> {
            service.sendPush(PushSendRequest(tenantId, userId))
        }
    }

    @Test
    fun `sendPush returns APPROVED immediately when the challenge is already resolved`() {
        val device = deviceEntity()
        whenever(repository.findFirstByTenantIdAndUserIdAndFcmTokenIsNotNullOrderByCreatedAtDesc(tenantId, userId)).thenReturn(device)
        val challenge = PushChallenge(UUID.randomUUID(), tenantId, userId, device.id, ChallengeStatus.PENDING, Instant.now())
        whenever(pushChallengeService.create(tenantId, userId, device.id)).thenReturn(challenge)
        whenever(pushChallengeService.find(challenge.challengeId)).thenReturn(challenge.copy(status = ChallengeStatus.APPROVED))

        val result = service.sendPush(PushSendRequest(tenantId, userId))

        assertEquals(PushResult.APPROVED, result.result)
    }

    @Test
    fun `sendPush times out when the challenge never resolves`() {
        val device = deviceEntity()
        whenever(repository.findFirstByTenantIdAndUserIdAndFcmTokenIsNotNullOrderByCreatedAtDesc(tenantId, userId)).thenReturn(device)
        val challenge = PushChallenge(UUID.randomUUID(), tenantId, userId, device.id, ChallengeStatus.PENDING, Instant.now())
        whenever(pushChallengeService.create(tenantId, userId, device.id)).thenReturn(challenge)
        whenever(pushChallengeService.find(challenge.challengeId)).thenReturn(challenge)

        val result = service.sendPush(PushSendRequest(tenantId, userId))

        assertEquals(PushResult.TIMEOUT, result.result)
    }

    @Test
    fun `respondToPush throws Conflict-mapped exception when already resolved`() {
        val challenge = PushChallenge(UUID.randomUUID(), tenantId, userId, UUID.randomUUID(), ChallengeStatus.APPROVED, Instant.now())
        whenever(pushChallengeService.find(challenge.challengeId)).thenReturn(challenge)

        assertThrows<ChallengeAlreadyResolvedException> {
            service.respondToPush(PushRespondRequest(challenge.challengeId, true))
        }
    }

    @Test
    fun `respondToPush throws NotFound-mapped exception for an unknown challenge`() {
        val challengeId = UUID.randomUUID()
        whenever(pushChallengeService.find(challengeId)).thenReturn(null)

        assertThrows<ChallengeNotFoundException> {
            service.respondToPush(PushRespondRequest(challengeId, true))
        }
    }

    private fun <T> eq(value: T): T = org.mockito.kotlin.eq(value)
}
