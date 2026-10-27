package com.iamplatform.identity

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.springframework.web.client.ResourceAccessException
import java.time.Clock
import java.time.Duration
import java.time.Instant
import java.time.ZoneOffset
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class UserServiceTest {

    private val repository = mock<UserRepository>()
    private val tenantClient = mock<TenantClient>()
    private val auditPublisher = mock<AuditPublisher>()
    private val passwordService = mock<PasswordService>()
    private val policyClient = mock<PolicyClient>()
    private val now = Instant.parse("2026-10-27T12:00:00Z")
    private val clock = Clock.fixed(now, ZoneOffset.UTC)
    private val service = UserService(repository, tenantClient, auditPublisher, passwordService, policyClient, clock)

    private fun settings(
        lockoutThreshold: Int = 0,
        lockoutDurationMinutes: Int = 15,
        lockoutPermanent: Boolean = false,
        minLength: Int = 8,
        digit: Boolean = false,
    ) = SecuritySettings(minLength, false, false, digit, false, lockoutThreshold, lockoutDurationMinutes, lockoutPermanent)

    init {
        // Platform defaults unless a test says otherwise.
        whenever(policyClient.securitySettings(any())).thenReturn(settings())
    }

    private val tenantId = UUID.randomUUID()

    @Test
    fun `createUser succeeds when the tenant exists and email is unused`() {
        whenever(tenantClient.exists(tenantId)).thenReturn(true)
        whenever(repository.existsByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(false)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.createUser(CreateUserRequest(tenantId, "a@acme.com", "Alice"))

        assertEquals("a@acme.com", result.email)
        assertEquals(UserStatus.ACTIVE, result.status)
        verify(auditPublisher, times(1)).publish(any<AuditEvent>())
    }

    @Test
    fun `createUser rejects a nonexistent tenant without touching the repository`() {
        whenever(tenantClient.exists(tenantId)).thenReturn(false)

        assertThrows<TenantNotFoundException> {
            service.createUser(CreateUserRequest(tenantId, "a@acme.com", "Alice"))
        }

        verify(repository, never()).save(any())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `createUser rejects a duplicate email within the same tenant`() {
        whenever(tenantClient.exists(tenantId)).thenReturn(true)
        whenever(repository.existsByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(true)

        assertThrows<EmailAlreadyExistsException> {
            service.createUser(CreateUserRequest(tenantId, "a@acme.com", "Alice"))
        }

        verify(repository, never()).save(any())
    }

    @Test
    fun `updateStatus publishes identity-status_changed with the transition`() {
        val id = UUID.randomUUID()
        val user = UserEntity(id = id, tenantId = tenantId, email = "a@acme.com", displayName = "Alice")
        whenever(repository.findById(id)).thenReturn(Optional.of(user))
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.updateStatus(id, UpdateStatusRequest(UserStatus.SUSPENDED))

        assertEquals(UserStatus.SUSPENDED, result.status)
        verify(auditPublisher, times(1)).publish(any<AuditEvent>())
    }

    @Test
    fun `createUser defaults role to USER when not specified`() {
        whenever(tenantClient.exists(tenantId)).thenReturn(true)
        whenever(repository.existsByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(false)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.createUser(CreateUserRequest(tenantId, "a@acme.com", "Alice"))

        assertEquals(UserRole.USER, result.role)
    }

    @Test
    fun `createUser honors an explicit ADMIN role`() {
        whenever(tenantClient.exists(tenantId)).thenReturn(true)
        whenever(repository.existsByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(false)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.createUser(CreateUserRequest(tenantId, "a@acme.com", "Alice", role = UserRole.ADMIN))

        assertEquals(UserRole.ADMIN, result.role)
    }

    @Test
    fun `updateRole publishes identity-role_changed with the transition`() {
        val id = UUID.randomUUID()
        val user = UserEntity(id = id, tenantId = tenantId, email = "a@acme.com", displayName = "Alice")
        whenever(repository.findById(id)).thenReturn(Optional.of(user))
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.updateRole(id, UpdateRoleRequest(UserRole.ADMIN))

        assertEquals(UserRole.ADMIN, result.role)
        verify(auditPublisher, times(1)).publish(any<AuditEvent>())
    }

    @Test
    fun `verifyPassword includes role on a correct password`() {
        val id = UUID.randomUUID()
        val user = UserEntity(id = id, tenantId = tenantId, email = "a@acme.com", displayName = "Alice", passwordHash = "stored-hash", role = UserRole.ADMIN)
        whenever(repository.findByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(user)
        whenever(passwordService.matches("correct", "stored-hash")).thenReturn(true)

        val result = service.verifyPassword(VerifyPasswordRequest(tenantId, "a@acme.com", "correct"))

        assertEquals(UserRole.ADMIN, result.role)
    }

    @Test
    fun `getUser throws when the user does not exist`() {
        val id = UUID.randomUUID()
        whenever(repository.findById(id)).thenReturn(Optional.empty())

        assertThrows<UserNotFoundException> {
            service.getUser(id)
        }
    }

    @Test
    fun `createUser hashes the password when one is provided`() {
        whenever(tenantClient.exists(tenantId)).thenReturn(true)
        whenever(repository.existsByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(false)
        whenever(passwordService.hash("hunter2pass")).thenReturn("hashed-value")
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.createUser(CreateUserRequest(tenantId, "a@acme.com", "Alice", "hunter2pass"))

        assertEquals("hashed-value", result.passwordHash)
    }

    @Test
    fun `createUser leaves passwordHash null when no password is provided`() {
        whenever(tenantClient.exists(tenantId)).thenReturn(true)
        whenever(repository.existsByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(false)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.createUser(CreateUserRequest(tenantId, "a@acme.com", "Alice"))

        assertNull(result.passwordHash)
        verify(passwordService, never()).hash(any())
    }

    @Test
    fun `setPassword hashes and stores the new password and publishes identity-password_set`() {
        val id = UUID.randomUUID()
        val user = UserEntity(id = id, tenantId = tenantId, email = "a@acme.com", displayName = "Alice")
        whenever(repository.findById(id)).thenReturn(Optional.of(user))
        whenever(passwordService.hash("newpassword")).thenReturn("new-hash")
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        service.setPassword(id, SetPasswordRequest("newpassword"))

        assertEquals("new-hash", user.passwordHash)
        verify(auditPublisher, times(1)).publish(any<AuditEvent>())
    }

    @Test
    fun `verifyPassword returns valid with userId and status on a correct password`() {
        val id = UUID.randomUUID()
        val user = UserEntity(id = id, tenantId = tenantId, email = "a@acme.com", displayName = "Alice", passwordHash = "stored-hash")
        whenever(repository.findByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(user)
        whenever(passwordService.matches("correct", "stored-hash")).thenReturn(true)

        val result = service.verifyPassword(VerifyPasswordRequest(tenantId, "a@acme.com", "correct"))

        assertEquals(true, result.valid)
        assertEquals(id, result.userId)
        assertEquals(UserStatus.ACTIVE, result.status)
    }

    @Test
    fun `verifyPassword returns invalid without userId on a wrong password`() {
        val id = UUID.randomUUID()
        val user = UserEntity(id = id, tenantId = tenantId, email = "a@acme.com", displayName = "Alice", passwordHash = "stored-hash")
        whenever(repository.findByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(user)
        whenever(passwordService.matches("wrong", "stored-hash")).thenReturn(false)

        val result = service.verifyPassword(VerifyPasswordRequest(tenantId, "a@acme.com", "wrong"))

        assertEquals(false, result.valid)
        assertNull(result.userId)
    }

    @Test
    fun `verifyPassword returns the same invalid shape for an unknown email as for a wrong password`() {
        whenever(repository.findByTenantIdAndEmail(tenantId, "ghost@acme.com")).thenReturn(null)

        val result = service.verifyPassword(VerifyPasswordRequest(tenantId, "ghost@acme.com", "anything"))

        assertEquals(false, result.valid)
        assertNull(result.userId)
        assertNull(result.status)
    }

    @Test
    fun `verifyPassword returns invalid when the user has no password set`() {
        val id = UUID.randomUUID()
        val user = UserEntity(id = id, tenantId = tenantId, email = "a@acme.com", displayName = "Alice", passwordHash = null)
        whenever(repository.findByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(user)

        val result = service.verifyPassword(VerifyPasswordRequest(tenantId, "a@acme.com", "anything"))

        assertEquals(false, result.valid)
        verify(passwordService, never()).matches(any(), any())
    }

    // ---- Password rules (FR-3.1) ----

    @Test
    fun `createUser rejects a password that breaks the tenant rules without hashing or saving`() {
        whenever(tenantClient.exists(tenantId)).thenReturn(true)
        whenever(repository.existsByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(false)
        whenever(policyClient.securitySettings(tenantId)).thenReturn(settings(minLength = 12, digit = true))

        assertThrows<WeakPasswordException> {
            service.createUser(CreateUserRequest(tenantId, "a@acme.com", "Alice", "longenoughbutnodigits"))
        }
        verify(passwordService, never()).hash(any())
        verify(repository, never()).save(any())
    }

    @Test
    fun `createUser fails closed when the tenant rules cannot be read`() {
        whenever(tenantClient.exists(tenantId)).thenReturn(true)
        whenever(repository.existsByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(false)
        whenever(policyClient.securitySettings(tenantId)).thenThrow(ResourceAccessException("policy-svc down"))

        assertThrows<ResourceAccessException> {
            service.createUser(CreateUserRequest(tenantId, "a@acme.com", "Alice", "validpassword1"))
        }
        verify(repository, never()).save(any())
    }

    @Test
    fun `setPassword rejects a weak password and leaves the existing one untouched`() {
        val id = UUID.randomUUID()
        val user = UserEntity(id = id, tenantId = tenantId, email = "a@acme.com", displayName = "Alice", passwordHash = "old-hash")
        whenever(repository.findById(id)).thenReturn(Optional.of(user))
        whenever(policyClient.securitySettings(tenantId)).thenReturn(settings(minLength = 14))

        assertThrows<WeakPasswordException> { service.setPassword(id, SetPasswordRequest("only12chars!")) }

        assertEquals("old-hash", user.passwordHash)
        verify(repository, never()).save(any())
    }

    // ---- Account lockout (FR-3.5) ----

    private fun userWith(attempts: Int = 0, lockedUntil: Instant? = null, permanent: Boolean = false) =
        UserEntity(
            id = UUID.randomUUID(), tenantId = tenantId, email = "a@acme.com", displayName = "Alice",
            passwordHash = "stored-hash", failedLoginAttempts = attempts, lockedUntil = lockedUntil, permanentlyLocked = permanent,
        ).also {
            whenever(repository.findByTenantIdAndEmail(tenantId, "a@acme.com")).thenReturn(it)
            whenever(repository.findById(it.id)).thenReturn(Optional.of(it))
            whenever(repository.save(any())).thenAnswer { inv -> inv.arguments[0] }
        }

    private fun wrongPassword() = service.verifyPassword(VerifyPasswordRequest(tenantId, "a@acme.com", "wrong"))
    private fun rightPassword() = service.verifyPassword(VerifyPasswordRequest(tenantId, "a@acme.com", "correct"))

    @Test
    fun `a wrong password is counted atomically in the database`() {
        val user = userWith()
        whenever(passwordService.matches("wrong", "stored-hash")).thenReturn(false)

        assertFalse(wrongPassword().valid)

        verify(repository).incrementFailedAttempts(user.id)
    }

    @Test
    fun `reaching the threshold locks the account for the configured time and audits it`() {
        // 3 is what the database holds after the increment for this attempt.
        val user = userWith(attempts = 3)
        whenever(passwordService.matches("wrong", "stored-hash")).thenReturn(false)
        whenever(policyClient.securitySettings(tenantId)).thenReturn(settings(lockoutThreshold = 3, lockoutDurationMinutes = 10))

        wrongPassword()

        assertEquals(now.plus(Duration.ofMinutes(10)), user.lockedUntil)
        assertEquals(0, user.failedLoginAttempts)
        assertFalse(user.permanentlyLocked)
        val captor = org.mockito.kotlin.argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("identity.account_locked", captor.firstValue.action)
    }

    @Test
    fun `below the threshold nothing is locked and nothing is audited`() {
        val user = userWith(attempts = 2)
        whenever(passwordService.matches("wrong", "stored-hash")).thenReturn(false)
        whenever(policyClient.securitySettings(tenantId)).thenReturn(settings(lockoutThreshold = 3))

        wrongPassword()

        assertNull(user.lockedUntil)
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `permanent lockout locks until an admin unlocks`() {
        val user = userWith(attempts = 5)
        whenever(passwordService.matches("wrong", "stored-hash")).thenReturn(false)
        whenever(policyClient.securitySettings(tenantId)).thenReturn(settings(lockoutThreshold = 5, lockoutPermanent = true))

        wrongPassword()

        assertTrue(user.permanentlyLocked)
        assertNull(user.lockedUntil)
    }

    @Test
    fun `with lockout off (threshold 0) many failures never lock`() {
        val user = userWith(attempts = 500)
        whenever(passwordService.matches("wrong", "stored-hash")).thenReturn(false)

        wrongPassword()

        assertNull(user.lockedUntil)
        assertFalse(user.permanentlyLocked)
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `an outage reading the lockout settings still counts the failure but does not lock or throw`() {
        val user = userWith(attempts = 9)
        whenever(passwordService.matches("wrong", "stored-hash")).thenReturn(false)
        whenever(policyClient.securitySettings(tenantId)).thenThrow(ResourceAccessException("policy-svc down"))

        assertFalse(wrongPassword().valid)

        verify(repository).incrementFailedAttempts(user.id)
        assertNull(user.lockedUntil)
    }

    @Test
    fun `a wrong guess on an already locked account is not counted and answers like any wrong password`() {
        val user = userWith(lockedUntil = now.plusSeconds(600))
        whenever(passwordService.matches("wrong", "stored-hash")).thenReturn(false)

        val result = wrongPassword()

        assertFalse(result.valid)
        assertFalse(result.locked)
        verify(repository, never()).incrementFailedAttempts(user.id)
    }

    @Test
    fun `the correct password on a temporarily locked account reports the lock and does not sign in`() {
        userWith(lockedUntil = now.plusSeconds(600))
        whenever(passwordService.matches("correct", "stored-hash")).thenReturn(true)

        val result = rightPassword()

        assertFalse(result.valid)
        assertTrue(result.locked)
        assertEquals(now.plusSeconds(600), result.lockedUntil)
        assertFalse(result.permanentlyLocked)
    }

    @Test
    fun `the correct password on a permanently locked account reports it`() {
        userWith(permanent = true)
        whenever(passwordService.matches("correct", "stored-hash")).thenReturn(true)

        val result = rightPassword()

        assertFalse(result.valid)
        assertTrue(result.locked)
        assertTrue(result.permanentlyLocked)
    }

    @Test
    fun `a correct password after the lock has expired signs in and clears the state`() {
        val user = userWith(attempts = 0, lockedUntil = now.minusSeconds(5))
        whenever(passwordService.matches("correct", "stored-hash")).thenReturn(true)

        val result = rightPassword()

        assertTrue(result.valid)
        assertNull(user.lockedUntil)
        verify(repository).save(user)
    }

    @Test
    fun `a correct password resets earlier failed attempts`() {
        val user = userWith(attempts = 2)
        whenever(passwordService.matches("correct", "stored-hash")).thenReturn(true)

        assertTrue(rightPassword().valid)

        assertEquals(0, user.failedLoginAttempts)
    }

    @Test
    fun `unlockUser clears the lock and the counter and audits it`() {
        val user = userWith(attempts = 4, lockedUntil = now.plusSeconds(600), permanent = true)

        service.unlockUser(user.id)

        assertEquals(0, user.failedLoginAttempts)
        assertNull(user.lockedUntil)
        assertFalse(user.permanentlyLocked)
        val captor = org.mockito.kotlin.argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("identity.account_unlocked", captor.firstValue.action)
    }
}
