package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class GoogleWorkspaceOuProvisioningServiceTest {

    private val configService = mock<GoogleWorkspaceConfigService>()
    private val directoryClient = mock<GoogleWorkspaceDirectoryClient>()
    private val identityClient = mock<IdentityClient>()
    private val deviceClient = mock<DeviceClient>()
    private val groupClient = mock<GroupClient>()
    private val provisioning = mock<ProvisioningService>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = GoogleWorkspaceOuProvisioningService(
        configService, directoryClient, identityClient, deviceClient, groupClient, provisioning, auditPublisher,
    )

    private val tenantId = UUID.randomUUID()
    private val adminId = UUID.randomUUID()
    private val key = GoogleServiceAccountKey("sa@x.iam.gserviceaccount.com", "pk", "kid")
    private val config = ProvisionGoogleUserRequest(
        domain = "demo.econz.net", adminEmail = "admin@demo.econz.net", orgUnitPath = "/Ratnesh Test",
        serviceAccountKey = key, primaryEmail = "", givenName = "", familyName = "",
    )

    private fun stubCommon() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(groupClient.listGroups(tenantId)).thenReturn(emptyList())
        whenever(groupClient.createGroup(tenantId, "Ratnesh Test")).thenReturn(RemoteGroup(UUID.randomUUID(), tenantId, "Ratnesh Test", java.time.Instant.now()))
    }

    @Test
    fun `an existing IAM user just gets their group updated -- no account creation, no device, no email`() {
        stubCommon()
        val existingId = UUID.randomUUID()
        whenever(directoryClient.listUsers("admin@demo.econz.net", key, "demo.econz.net")).thenReturn(
            listOf(RemoteGoogleDirectoryUser("ada@demo.econz.net", "Ada", "/Ratnesh Test", suspended = false)),
        )
        whenever(identityClient.listUsers(tenantId)).thenReturn(
            listOf(RemoteUserListEntry(existingId, tenantId, "ADA@demo.econz.net", "Ada", RemoteUserStatus.ACTIVE, RemoteUserRole.USER)),
        )

        val result = service.syncOrgUnit(tenantId, "/Ratnesh Test", adminId, "1.2.3.4")

        assertEquals(listOf("ada@demo.econz.net"), result.matched)
        assertEquals(emptyList(), result.created)
        verify(groupClient).assignGroup(eq(existingId), any())
        verify(identityClient, never()).createUser(any())
        verify(deviceClient, never()).enroll(any(), any())
        verify(directoryClient, never()).sendEmail(any(), any(), any(), any(), any(), any())
    }

    @Test
    fun `a Google user with no IAM account gets created, enrolled, pushed to apps, grouped, and emailed`() {
        stubCommon()
        whenever(directoryClient.listUsers("admin@demo.econz.net", key, "demo.econz.net")).thenReturn(
            listOf(RemoteGoogleDirectoryUser("new.hire@demo.econz.net", "New Hire", "/Ratnesh Test", suspended = false)),
        )
        whenever(identityClient.listUsers(tenantId)).thenReturn(emptyList())
        val createdId = UUID.randomUUID()
        whenever(identityClient.createUser(any())).thenReturn(
            CreatedRemoteUser(createdId, tenantId, "new.hire@demo.econz.net", "New Hire", RemoteUserRole.USER),
        )
        whenever(deviceClient.enroll(tenantId, createdId)).thenReturn(
            RemoteEnrollResponse(UUID.randomUUID(), "PENDING", "SECRET", "otpauth://totp/x"),
        )

        val result = service.syncOrgUnit(tenantId, "/Ratnesh Test", adminId, "1.2.3.4")

        assertEquals(listOf("new.hire@demo.econz.net"), result.created)
        assertEquals(emptyList(), result.createdButEmailFailed)

        val createCaptor = argumentCaptor<CreateRemoteUserRequest>()
        verify(identityClient).createUser(createCaptor.capture())
        assertEquals(RemoteUserRole.USER, createCaptor.firstValue.role)
        assertTrue(createCaptor.firstValue.password!!.length >= 16)

        verify(deviceClient).enroll(tenantId, createdId)
        verify(groupClient).assignGroup(eq(createdId), any())
        verify(provisioning).reconcile(ProvisionUser(createdId, tenantId, "new.hire@demo.econz.net", "New Hire", active = true))
        verify(directoryClient).sendEmail(eq("admin@demo.econz.net"), eq(key), eq("new.hire@demo.econz.net"), any(), any(), eq("otpauth://totp/x"))
    }

    @Test
    fun `the account still counts as created even when the email fails to send`() {
        stubCommon()
        whenever(directoryClient.listUsers("admin@demo.econz.net", key, "demo.econz.net")).thenReturn(
            listOf(RemoteGoogleDirectoryUser("unreachable@demo.econz.net", null, "/Ratnesh Test", suspended = false)),
        )
        whenever(identityClient.listUsers(tenantId)).thenReturn(emptyList())
        val createdId = UUID.randomUUID()
        whenever(identityClient.createUser(any())).thenReturn(
            CreatedRemoteUser(createdId, tenantId, "unreachable@demo.econz.net", "unreachable", RemoteUserRole.USER),
        )
        whenever(deviceClient.enroll(tenantId, createdId)).thenReturn(
            RemoteEnrollResponse(UUID.randomUUID(), "PENDING", "SECRET", "otpauth://totp/x"),
        )
        whenever(directoryClient.sendEmail(any(), any(), any(), any(), any(), any()))
            .thenThrow(GoogleProvisioningException("quota exceeded"))

        val result = service.syncOrgUnit(tenantId, "/Ratnesh Test", adminId, "1.2.3.4")

        assertEquals(emptyList(), result.created)
        assertEquals(listOf("unreachable@demo.econz.net"), result.createdButEmailFailed)
        // The account itself was still created and provisioned -- not rolled back over the email failure.
        verify(identityClient).createUser(any())
        verify(groupClient).assignGroup(eq(createdId), any())
    }

    @Test
    fun `users outside the requested OU are never touched`() {
        stubCommon()
        whenever(directoryClient.listUsers("admin@demo.econz.net", key, "demo.econz.net")).thenReturn(
            listOf(
                RemoteGoogleDirectoryUser("in-ou@demo.econz.net", "In", "/Ratnesh Test", suspended = false),
                RemoteGoogleDirectoryUser("elsewhere@demo.econz.net", "Else", "/Sales Interns", suspended = false),
            ),
        )
        whenever(identityClient.listUsers(tenantId)).thenReturn(emptyList())
        whenever(identityClient.createUser(any())).thenReturn(
            CreatedRemoteUser(UUID.randomUUID(), tenantId, "in-ou@demo.econz.net", "In", RemoteUserRole.USER),
        )
        whenever(deviceClient.enroll(any(), any())).thenReturn(RemoteEnrollResponse(UUID.randomUUID(), "PENDING", "S", "otpauth://totp/x"))

        val result = service.syncOrgUnit(tenantId, "/Ratnesh Test", adminId, null)

        assertEquals(listOf("in-ou@demo.econz.net"), result.created)
    }

    @Test
    fun `refuses to touch anything when Google Workspace is not configured for this tenant`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(null)

        assertThrows<GoogleWorkspaceConfigNotFoundException> { service.syncOrgUnit(tenantId, "/Ratnesh Test", adminId, null) }
        verify(identityClient, never()).createUser(any())
        verify(groupClient, never()).createGroup(any(), any())
    }

    @Test
    fun `publishes one audit event summarizing the run, as the acting admin`() {
        stubCommon()
        whenever(directoryClient.listUsers("admin@demo.econz.net", key, "demo.econz.net")).thenReturn(emptyList())
        whenever(identityClient.listUsers(tenantId)).thenReturn(emptyList())

        service.syncOrgUnit(tenantId, "/Ratnesh Test", adminId, "9.9.9.9")

        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("google_workspace.ou_synced_by_admin", captor.firstValue.action)
        assertEquals(adminId.toString(), captor.firstValue.actorId)
        assertEquals("9.9.9.9", captor.firstValue.sourceIp)
    }

    private fun <T> eq(value: T): T = org.mockito.kotlin.eq(value)
}
