package com.iamplatform.identity

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UserServiceTest {

    private val repository = mock<UserRepository>()
    private val tenantClient = mock<TenantClient>()
    private val auditPublisher = mock<AuditPublisher>()
    private val passwordService = mock<PasswordService>()
    private val service = UserService(repository, tenantClient, auditPublisher, passwordService)

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
}
