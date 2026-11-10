package com.iamplatform.tenant

import jakarta.servlet.http.HttpServletRequest
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID

class GroupControllerTest {

    private val groupClient = mock<GroupClient>()
    private val adminAccessGuard = mock<AdminAccessGuard>()
    private val oidcClientGroupRepository = mock<OidcClientGroupRepository>()
    private val samlSpGroupRepository = mock<SamlSpGroupRepository>()
    private val groupPushService = mock<GoogleWorkspaceGroupPushService>()
    private val controller = GroupController(groupClient, adminAccessGuard, oidcClientGroupRepository, samlSpGroupRepository, groupPushService)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val groupId = UUID.randomUUID()

    @Test
    fun `assigning a user to a group also fires the best-effort Google push hook`() {
        whenever(groupClient.assignGroup(userId, groupId)).thenReturn(RemoteUser(userId, tenantId, RemoteUserRole.USER, groupId = groupId, email = "ada@demo.econz.net"))

        controller.assignGroup(userId, tenantId, AssignGroupAdminRequest(groupId), "tok")

        verify(groupPushService).onMemberAssigned(tenantId, groupId, "ada@demo.econz.net")
    }

    @Test
    fun `removing a user from a group (null groupId) does NOT fire the push hook`() {
        whenever(groupClient.assignGroup(userId, null)).thenReturn(RemoteUser(userId, tenantId, RemoteUserRole.USER, groupId = null, email = "ada@demo.econz.net"))

        controller.assignGroup(userId, tenantId, AssignGroupAdminRequest(null), "tok")

        verify(groupPushService, never()).onMemberAssigned(any(), any(), any())
    }

    @Test
    fun `deleting a group's org unit is a separate action from deleting the IAM group`() {
        val adminId = UUID.randomUUID()
        whenever(adminAccessGuard.requireValidSession("tok"))
            .thenReturn(RemoteSession(UUID.randomUUID(), tenantId, adminId, Instant.now().plusSeconds(3600)))
        val httpRequest = mock<HttpServletRequest>()
        whenever(httpRequest.remoteAddr).thenReturn("1.2.3.4")

        controller.deleteGroupOrgUnit(groupId, tenantId, "tok", httpRequest)

        verify(groupPushService).deleteOrgUnitForGroup(any(), any(), any(), any())
        verify(groupClient, never()).deleteGroup(any())
    }
}
