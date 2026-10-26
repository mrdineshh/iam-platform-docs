package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID

class AdminAccessGuardTest {

    private val sessionClient = mock<SessionClient>()
    private val identityClient = mock<IdentityClient>()
    private val guard = AdminAccessGuard(sessionClient, identityClient)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()

    @Test
    fun `passes for a live session belonging to this tenant with an ADMIN user`() {
        whenever(sessionClient.find("tok")).thenReturn(RemoteSession(UUID.randomUUID(), tenantId, userId, Instant.now().plusSeconds(3600)))
        whenever(identityClient.findUser(userId)).thenReturn(RemoteUser(userId, tenantId, RemoteUserRole.ADMIN))

        guard.requireTenantAdmin("tok", tenantId)
    }

    @Test
    fun `rejects an unknown or expired session`() {
        whenever(sessionClient.find("tok")).thenReturn(null)

        assertThrows<AdminSessionInvalidException> {
            guard.requireTenantAdmin("tok", tenantId)
        }
    }

    @Test
    fun `rejects a session belonging to a different tenant`() {
        whenever(sessionClient.find("tok")).thenReturn(RemoteSession(UUID.randomUUID(), UUID.randomUUID(), userId, Instant.now().plusSeconds(3600)))

        assertThrows<AdminAccessDeniedException> {
            guard.requireTenantAdmin("tok", tenantId)
        }
    }

    @Test
    fun `rejects a non-ADMIN user`() {
        whenever(sessionClient.find("tok")).thenReturn(RemoteSession(UUID.randomUUID(), tenantId, userId, Instant.now().plusSeconds(3600)))
        whenever(identityClient.findUser(userId)).thenReturn(RemoteUser(userId, tenantId, RemoteUserRole.USER))

        assertThrows<AdminAccessDeniedException> {
            guard.requireTenantAdmin("tok", tenantId)
        }
    }
}
