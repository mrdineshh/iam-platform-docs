package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals

class GoogleWorkspaceGroupPushServiceTest {

    private val configService = mock<GoogleWorkspaceConfigService>()
    private val directoryClient = mock<GoogleWorkspaceDirectoryClient>()
    private val groupClient = mock<GroupClient>()
    private val identityClient = mock<IdentityClient>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = GoogleWorkspaceGroupPushService(configService, directoryClient, groupClient, identityClient, auditPublisher)

    private val tenantId = UUID.randomUUID()
    private val groupId = UUID.randomUUID()
    private val adminId = UUID.randomUUID()
    private val key = GoogleServiceAccountKey("sa@x.iam.gserviceaccount.com", "pk", "kid")
    private val config = ProvisionGoogleUserRequest(
        domain = "demo.econz.net", adminEmail = "admin@demo.econz.net", orgUnitPath = null,
        serviceAccountKey = key, primaryEmail = "", givenName = "", familyName = "",
    )

    private fun member(email: String) =
        RemoteUserListEntry(UUID.randomUUID(), tenantId, email, email.substringBefore('@'), RemoteUserStatus.ACTIVE, RemoteUserRole.USER, groupId = groupId)

    @Test
    fun `creates the OU when none exists, and moves every current member who has a Google account`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(groupClient.listGroups(tenantId)).thenReturn(listOf(RemoteGroup(groupId, tenantId, "Ratnesh Test", Instant.now())))
        whenever(directoryClient.ensureOrgUnit("admin@demo.econz.net", key, "Ratnesh Test")).thenReturn(OrgUnitEnsureResult("/Ratnesh Test", created = true))
        whenever(identityClient.listUsers(tenantId)).thenReturn(
            listOf(member("ada@demo.econz.net"), member("bo@demo.econz.net"), member("notinthistenant@other.net").copy(groupId = UUID.randomUUID())),
        )
        whenever(directoryClient.moveToOrgUnit("admin@demo.econz.net", key, "ada@demo.econz.net", "/Ratnesh Test")).thenReturn(true)
        whenever(directoryClient.moveToOrgUnit("admin@demo.econz.net", key, "bo@demo.econz.net", "/Ratnesh Test")).thenReturn(false)

        val result = service.pushGroupToOrgUnit(tenantId, groupId, adminId, "1.2.3.4")

        assertEquals("Ratnesh Test", result.groupName)
        assertEquals("/Ratnesh Test", result.orgUnitPath)
        assertEquals(true, result.created)
        assertEquals(listOf("ada@demo.econz.net"), result.moved)
        assertEquals(listOf("bo@demo.econz.net"), result.skipped)
        // Only the two actual members of THIS group were ever considered.
        verify(directoryClient, never()).moveToOrgUnit(any(), any(), eq("notinthistenant@other.net"), any())
    }

    @Test
    fun `reuses the OU rather than creating a duplicate when one already exists`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(groupClient.listGroups(tenantId)).thenReturn(listOf(RemoteGroup(groupId, tenantId, "Ratnesh Test", Instant.now())))
        whenever(directoryClient.ensureOrgUnit("admin@demo.econz.net", key, "Ratnesh Test")).thenReturn(OrgUnitEnsureResult("/Ratnesh Test", created = false))
        whenever(identityClient.listUsers(tenantId)).thenReturn(emptyList())

        val result = service.pushGroupToOrgUnit(tenantId, groupId, adminId, null)

        assertEquals(false, result.created)
    }

    @Test
    fun `a member whose email is outside the configured Google domain is skipped without calling Google`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(groupClient.listGroups(tenantId)).thenReturn(listOf(RemoteGroup(groupId, tenantId, "Ratnesh Test", Instant.now())))
        whenever(directoryClient.ensureOrgUnit(any(), any(), any())).thenReturn(OrgUnitEnsureResult("/Ratnesh Test", created = false))
        whenever(identityClient.listUsers(tenantId)).thenReturn(listOf(member("outsider@gmail.com")))

        val result = service.pushGroupToOrgUnit(tenantId, groupId, adminId, null)

        assertEquals(listOf("outsider@gmail.com"), result.skipped)
        verify(directoryClient, never()).moveToOrgUnit(any(), any(), eq("outsider@gmail.com"), any())
    }

    @Test
    fun `refuses to proceed for an unknown group`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(groupClient.listGroups(tenantId)).thenReturn(emptyList())

        assertThrows<GroupNotFoundException> { service.pushGroupToOrgUnit(tenantId, groupId, adminId, null) }
        verify(directoryClient, never()).ensureOrgUnit(any(), any(), any())
    }

    @Test
    fun `refuses to proceed when Google Workspace is not configured for this tenant`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(null)

        assertThrows<GoogleWorkspaceConfigNotFoundException> { service.pushGroupToOrgUnit(tenantId, groupId, adminId, null) }
        verify(groupClient, never()).listGroups(any())
    }

    @Test
    fun `publishes one audit event summarizing the push, as the acting admin`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(groupClient.listGroups(tenantId)).thenReturn(listOf(RemoteGroup(groupId, tenantId, "Ratnesh Test", Instant.now())))
        whenever(directoryClient.ensureOrgUnit(any(), any(), any())).thenReturn(OrgUnitEnsureResult("/Ratnesh Test", created = true))
        whenever(identityClient.listUsers(tenantId)).thenReturn(emptyList())

        service.pushGroupToOrgUnit(tenantId, groupId, adminId, "9.9.9.9")

        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("google_workspace.group_pushed_to_ou_by_admin", captor.firstValue.action)
        assertEquals(adminId.toString(), captor.firstValue.actorId)
        assertEquals("9.9.9.9", captor.firstValue.sourceIp)
    }

    // ---- onMemberAssigned: the automatic hook called right after a group assignment ----

    @Test
    fun `onMemberAssigned moves the one new member into the group's OU, creating it if needed`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(groupClient.listGroups(tenantId)).thenReturn(listOf(RemoteGroup(groupId, tenantId, "Ratnesh Test", Instant.now())))
        whenever(directoryClient.ensureOrgUnit("admin@demo.econz.net", key, "Ratnesh Test")).thenReturn(OrgUnitEnsureResult("/Ratnesh Test", created = true))

        service.onMemberAssigned(tenantId, groupId, "ada@demo.econz.net")

        verify(directoryClient).moveToOrgUnit("admin@demo.econz.net", key, "ada@demo.econz.net", "/Ratnesh Test")
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("google_workspace.member_auto_pushed_to_ou", captor.firstValue.action)
        assertEquals(AuditResult.SUCCESS, captor.firstValue.result)
    }

    @Test
    fun `onMemberAssigned does nothing -- not even a lookup -- when Google Workspace isn't configured`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(null)

        service.onMemberAssigned(tenantId, groupId, "ada@demo.econz.net")

        verify(groupClient, never()).listGroups(any())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `onMemberAssigned does nothing for an email outside the configured Google domain`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)

        service.onMemberAssigned(tenantId, groupId, "outsider@gmail.com")

        verify(directoryClient, never()).ensureOrgUnit(any(), any(), any())
    }

    @Test
    fun `onMemberAssigned never throws, even when the Google call fails -- it only audits the failure`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(groupClient.listGroups(tenantId)).thenReturn(listOf(RemoteGroup(groupId, tenantId, "Ratnesh Test", Instant.now())))
        whenever(directoryClient.ensureOrgUnit(any(), any(), any())).thenThrow(GoogleProvisioningException("quota exceeded"))

        service.onMemberAssigned(tenantId, groupId, "ada@demo.econz.net") // must not throw

        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals(AuditResult.FAILURE, captor.firstValue.result)
    }

    // ---- deleteOrgUnitForGroup ----

    @Test
    fun `deleteOrgUnitForGroup deletes the OU matching the group's name and audits it`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(groupClient.listGroups(tenantId)).thenReturn(listOf(RemoteGroup(groupId, tenantId, "Ratnesh Test", Instant.now())))
        whenever(directoryClient.deleteOrgUnit("admin@demo.econz.net", key, "Ratnesh Test")).thenReturn(true)

        val deleted = service.deleteOrgUnitForGroup(tenantId, groupId, adminId, "1.2.3.4")

        assertEquals(true, deleted)
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("google_workspace.group_ou_deleted_by_admin", captor.firstValue.action)
    }

    @Test
    fun `a non-empty OU's refusal from Google surfaces as a real error, not a silent no-op`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(groupClient.listGroups(tenantId)).thenReturn(listOf(RemoteGroup(groupId, tenantId, "Ratnesh Test", Instant.now())))
        whenever(directoryClient.deleteOrgUnit(any(), any(), any())).thenThrow(GoogleProvisioningException("org unit not empty"))

        assertThrows<GoogleProvisioningException> { service.deleteOrgUnitForGroup(tenantId, groupId, adminId, null) }
    }

    private fun <T> eq(value: T): T = org.mockito.kotlin.eq(value)
}
