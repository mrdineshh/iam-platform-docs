package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import jakarta.servlet.http.HttpServletRequest
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SessionManagementControllerTest {

    private val sessionClient = mock<SessionClient>()
    private val identityClient = mock<IdentityClient>()
    private val adminAccessGuard = mock<AdminAccessGuard>()
    private val auditPublisher = mock<AuditPublisher>()
    private val httpRequest = mock<HttpServletRequest>()
    private val controller = SessionManagementController(sessionClient, identityClient, adminAccessGuard, auditPublisher)

    private val tenantId = UUID.randomUUID()
    private val adminId = UUID.randomUUID()
    private val targetId = UUID.randomUUID()
    private val adminSessionId = UUID.randomUUID()

    private fun record(user: UUID = targetId, id: UUID = UUID.randomUUID()) =
        RemoteSessionRecord(id, tenantId, user, "8.8.8.8", null, Instant.now(), Instant.now().plusSeconds(3600))

    private fun givenAdminCaller() {
        whenever(adminAccessGuard.requireValidSession("admin-tok"))
            .thenReturn(RemoteSession(adminSessionId, tenantId, adminId, Instant.now().plusSeconds(3600)))
        whenever(identityClient.findUser(targetId)).thenReturn(RemoteUser(targetId, tenantId, RemoteUserRole.USER))
    }

    @Test
    fun `an admin cannot list sessions of a user from another tenant`() {
        givenAdminCaller()
        whenever(identityClient.findUser(targetId)).thenReturn(RemoteUser(targetId, UUID.randomUUID(), RemoteUserRole.USER))

        assertThrows<UserNotFoundForDeletionException> { controller.listUserSessions(targetId, tenantId, "admin-tok") }
        verify(sessionClient, never()).listForUser(any(), any())
    }

    @Test
    fun `an admin cannot revoke sessions of an unknown user`() {
        givenAdminCaller()
        whenever(identityClient.findUser(targetId)).thenReturn(null)

        assertThrows<UserNotFoundForDeletionException> { controller.revokeAllUserSessions(targetId, tenantId, "admin-tok", httpRequest) }
        verify(sessionClient, never()).terminateAllForUser(any(), any(), any())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `revoking all sessions ends them and audits with the admin as actor`() {
        givenAdminCaller()
        whenever(sessionClient.listForUser(tenantId, targetId)).thenReturn(listOf(record(), record()))

        val response = controller.revokeAllUserSessions(targetId, tenantId, "admin-tok", httpRequest)

        assertEquals(2, response.body!!.revoked)
        verify(sessionClient).terminateAllForUser(eq(tenantId), eq(targetId), eq("admin-revoked-by-$adminId"))
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("session.revoked_by_admin", captor.firstValue.action)
        assertEquals(ActorType.ADMIN, captor.firstValue.actorType)
        assertEquals(adminId.toString(), captor.firstValue.actorId)
    }

    @Test
    fun `revoking one session audits it and passes the session id through`() {
        givenAdminCaller()
        val sessionId = UUID.randomUUID()

        controller.revokeUserSession(targetId, sessionId, tenantId, "admin-tok", httpRequest)

        verify(sessionClient).terminateOneForUser(eq(tenantId), eq(targetId), eq(sessionId), any())
        verify(auditPublisher).publish(any())
    }

    @Test
    fun `my sessions marks the caller's own session as current`() {
        val mine = UUID.randomUUID()
        whenever(adminAccessGuard.requireValidSession("tok"))
            .thenReturn(RemoteSession(mine, tenantId, targetId, Instant.now().plusSeconds(3600)))
        whenever(sessionClient.listForUser(tenantId, targetId)).thenReturn(listOf(record(id = mine), record()))

        val result = controller.listMySessions("tok").body!!

        assertTrue(result.first { it.sessionId == mine }.current)
        assertFalse(result.first { it.sessionId != mine }.current)
    }

    @Test
    fun `sign out of other devices keeps the current session`() {
        val mine = UUID.randomUUID()
        val other1 = UUID.randomUUID()
        val other2 = UUID.randomUUID()
        whenever(adminAccessGuard.requireValidSession("tok"))
            .thenReturn(RemoteSession(mine, tenantId, targetId, Instant.now().plusSeconds(3600)))
        whenever(sessionClient.listForUser(tenantId, targetId))
            .thenReturn(listOf(record(id = mine), record(id = other1), record(id = other2)))

        val result = controller.revokeMyOtherSessions("tok").body!!

        assertEquals(2, result.revoked)
        verify(sessionClient, never()).terminateOneForUser(any(), any(), eq(mine), any())
        verify(sessionClient).terminateOneForUser(eq(tenantId), eq(targetId), eq(other1), any())
        verify(sessionClient).terminateOneForUser(eq(tenantId), eq(targetId), eq(other2), any())
    }

    @Test
    fun `sign out of other devices tolerates a session that already ended`() {
        val mine = UUID.randomUUID()
        val gone = UUID.randomUUID()
        whenever(adminAccessGuard.requireValidSession("tok"))
            .thenReturn(RemoteSession(mine, tenantId, targetId, Instant.now().plusSeconds(3600)))
        whenever(sessionClient.listForUser(tenantId, targetId)).thenReturn(listOf(record(id = mine), record(id = gone)))
        whenever(sessionClient.terminateOneForUser(eq(tenantId), eq(targetId), eq(gone), any()))
            .thenThrow(SessionNotFoundForRevokeException())

        assertEquals(0, controller.revokeMyOtherSessions("tok").body!!.revoked)
    }
}
