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
import org.mockito.kotlin.inOrder
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UserLifecycleControllerTest {

    private val identityClient = mock<IdentityClient>()
    private val sessionClient = mock<SessionClient>()
    private val adminAccessGuard = mock<AdminAccessGuard>()
    private val googleConfigService = mock<GoogleWorkspaceConfigService>()
    private val googleClient = mock<GoogleWorkspaceDirectoryClient>()
    private val provisioning = mock<ProvisioningService>()
    private val scimConnections = mock<ScimConnectionService>()
    private val auditPublisher = mock<AuditPublisher>()
    private val httpRequest = mock<HttpServletRequest>()
    private val controller = UserLifecycleController(
        identityClient, sessionClient, adminAccessGuard, googleConfigService, googleClient, provisioning, scimConnections, auditPublisher,
    )

    private val tenantId = UUID.randomUUID()
    private val adminId = UUID.randomUUID()
    private val targetId = UUID.randomUUID()

    private fun givenAdmin(email: String = "ada@econz.net") {
        whenever(adminAccessGuard.requireValidSession("tok"))
            .thenReturn(RemoteSession(UUID.randomUUID(), tenantId, adminId, Instant.now().plusSeconds(3600)))
        whenever(identityClient.findUser(targetId)).thenReturn(
            RemoteUser(targetId, tenantId, RemoteUserRole.USER, email = email, displayName = "Ada Lovelace", status = RemoteUserStatus.ACTIVE),
        )
        whenever(provisioning.reconcile(any())).thenReturn(listOf(TargetResult("Pulse", "suspended", ok = true)))
        whenever(sessionClient.listForUser(tenantId, targetId)).thenReturn(emptyList())
    }

    @Test
    fun `suspending marks the user suspended, ends their sessions, and propagates to the apps`() {
        givenAdmin()
        whenever(sessionClient.listForUser(tenantId, targetId)).thenReturn(
            listOf(
                RemoteSessionRecord(UUID.randomUUID(), tenantId, targetId, "1.1.1.1", null, Instant.now(), Instant.now().plusSeconds(60)),
                RemoteSessionRecord(UUID.randomUUID(), tenantId, targetId, "2.2.2.2", null, Instant.now(), Instant.now().plusSeconds(60)),
            ),
        )

        val response = controller.suspend(targetId, tenantId, "tok", httpRequest).body!!

        assertEquals("SUSPENDED", response.status)
        assertEquals(2, response.sessionsEnded)
        inOrder(identityClient, sessionClient, provisioning) {
            verify(identityClient).updateStatus(targetId, RemoteUserStatus.SUSPENDED)
            verify(sessionClient).terminateAllForUser(eq(tenantId), eq(targetId), eq("suspended-by-admin-$adminId"))
            verify(provisioning).reconcile(ProvisionUser(targetId, tenantId, "ada@econz.net", "Ada Lovelace", active = false))
        }
    }

    @Test
    fun `suspending is audited with the admin as actor`() {
        givenAdmin()

        controller.suspend(targetId, tenantId, "tok", httpRequest)

        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("identity.suspended_by_admin", captor.firstValue.action)
        assertEquals(ActorType.ADMIN, captor.firstValue.actorType)
        assertEquals(adminId.toString(), captor.firstValue.actorId)
    }

    @Test
    fun `reactivating restores the status and does not touch sessions`() {
        givenAdmin()
        whenever(provisioning.reconcile(any())).thenReturn(listOf(TargetResult("Pulse", "reactivated", ok = true)))

        val response = controller.reactivate(targetId, tenantId, "tok", httpRequest).body!!

        assertEquals("ACTIVE", response.status)
        verify(identityClient).updateStatus(targetId, RemoteUserStatus.ACTIVE)
        verify(sessionClient, never()).terminateAllForUser(any(), any(), any())
        verify(provisioning).reconcile(ProvisionUser(targetId, tenantId, "ada@econz.net", "Ada Lovelace", active = true))
    }

    @Test
    fun `an admin cannot suspend their own account`() {
        givenAdmin()
        whenever(identityClient.findUser(adminId)).thenReturn(RemoteUser(adminId, tenantId, RemoteUserRole.ADMIN))

        assertThrows<CannotSuspendSelfException> { controller.suspend(adminId, tenantId, "tok", httpRequest) }

        verify(identityClient, never()).updateStatus(any(), any())
    }

    @Test
    fun `a user from another tenant or an unknown user is not found, and nothing changes`() {
        givenAdmin()
        whenever(identityClient.findUser(targetId)).thenReturn(RemoteUser(targetId, UUID.randomUUID(), RemoteUserRole.USER))
        assertThrows<UserNotFoundForDeletionException> { controller.suspend(targetId, tenantId, "tok", httpRequest) }

        whenever(identityClient.findUser(targetId)).thenReturn(null)
        assertThrows<UserNotFoundForDeletionException> { controller.suspend(targetId, tenantId, "tok", httpRequest) }

        verify(identityClient, never()).updateStatus(any(), any())
        verify(sessionClient, never()).terminateAllForUser(any(), any(), any())
    }

    @Test
    fun `Google Workspace is suspended too when configured, and its result is reported`() {
        givenAdmin("ada@demo.econz.net")
        val key = GoogleServiceAccountKey("sa@x", "pk", "kid")
        whenever(googleConfigService.loadProvisioningConfig(tenantId))
            .thenReturn(ProvisionGoogleUserRequest("demo.econz.net", "admin@demo.econz.net", null, key, "", "", ""))
        whenever(googleClient.setSuspended("admin@demo.econz.net", key, "ada@demo.econz.net", true)).thenReturn(true)

        val response = controller.suspend(targetId, tenantId, "tok", httpRequest).body!!

        assertEquals("Google Workspace", response.targets.first().target)
        assertEquals("suspended", response.targets.first().action)
        assertTrue(response.targets.first().ok)
    }

    @Test
    fun `a Google failure is reported but does not undo the suspension`() {
        givenAdmin("ada@demo.econz.net")
        val key = GoogleServiceAccountKey("sa@x", "pk", "kid")
        whenever(googleConfigService.loadProvisioningConfig(tenantId))
            .thenReturn(ProvisionGoogleUserRequest("demo.econz.net", "admin@demo.econz.net", null, key, "", "", ""))
        whenever(googleClient.setSuspended(any(), any(), any(), any())).thenThrow(GoogleProvisioningException("quota"))

        val response = controller.suspend(targetId, tenantId, "tok", httpRequest).body!!

        assertEquals("SUSPENDED", response.status)
        assertFalse(response.targets.first().ok)
        verify(identityClient).updateStatus(targetId, RemoteUserStatus.SUSPENDED)
    }

    @Test
    fun `a user who has no Google account is skipped, not treated as an error`() {
        givenAdmin("ada@demo.econz.net")
        val key = GoogleServiceAccountKey("sa@x", "pk", "kid")
        whenever(googleConfigService.loadProvisioningConfig(tenantId))
            .thenReturn(ProvisionGoogleUserRequest("demo.econz.net", "admin@demo.econz.net", null, key, "", "", ""))
        whenever(googleClient.setSuspended(any(), any(), any(), any())).thenReturn(false)

        val google = controller.suspend(targetId, tenantId, "tok", httpRequest).body!!.targets.first()

        assertEquals("skipped", google.action)
        assertTrue(google.ok)
    }

    @Test
    fun `a user whose email is not on the Google domain is skipped without calling Google`() {
        givenAdmin("ada@econz.net")
        val key = GoogleServiceAccountKey("sa@x", "pk", "kid")
        whenever(googleConfigService.loadProvisioningConfig(tenantId))
            .thenReturn(ProvisionGoogleUserRequest("demo.econz.net", "admin@demo.econz.net", null, key, "", "", ""))

        val google = controller.suspend(targetId, tenantId, "tok", httpRequest).body!!.targets.first()

        assertEquals("skipped", google.action)
        assertTrue(google.ok)
        verify(googleClient, never()).setSuspended(any(), any(), any(), any())
    }

    @Test
    fun `retry re-reconciles using the user's current status`() {
        givenAdmin()
        whenever(identityClient.findUser(targetId)).thenReturn(
            RemoteUser(targetId, tenantId, RemoteUserRole.USER, email = "ada@econz.net", displayName = "Ada Lovelace", status = RemoteUserStatus.SUSPENDED),
        )

        controller.retry(targetId, tenantId, "tok")

        verify(provisioning).reconcile(ProvisionUser(targetId, tenantId, "ada@econz.net", "Ada Lovelace", active = false))
    }
}
