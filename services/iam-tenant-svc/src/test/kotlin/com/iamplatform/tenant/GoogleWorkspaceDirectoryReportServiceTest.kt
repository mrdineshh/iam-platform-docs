package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyNoInteractions
import org.mockito.kotlin.whenever
import java.util.UUID
import kotlin.test.assertEquals

class GoogleWorkspaceDirectoryReportServiceTest {

    private val configService = mock<GoogleWorkspaceConfigService>()
    private val directoryClient = mock<GoogleWorkspaceDirectoryClient>()
    private val service = GoogleWorkspaceDirectoryReportService(configService, directoryClient)

    private val tenantId = UUID.randomUUID()
    private val key = GoogleServiceAccountKey("sa@x.iam.gserviceaccount.com", "pk", "kid")
    private val config = ProvisionGoogleUserRequest(
        domain = "demo.econz.net", adminEmail = "admin@demo.econz.net", orgUnitPath = "/Ratnesh Test",
        serviceAccountKey = key, primaryEmail = "", givenName = "", familyName = "",
    )

    @Test
    fun `groups users by their current OU and sorts each group by email`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(directoryClient.listUsers("admin@demo.econz.net", key, "demo.econz.net")).thenReturn(
            listOf(
                RemoteGoogleDirectoryUser("zara@demo.econz.net", "Zara", "/Ratnesh Test", suspended = false),
                RemoteGoogleDirectoryUser("ada@demo.econz.net", "Ada", "/Ratnesh Test", suspended = true),
                RemoteGoogleDirectoryUser("bo@demo.econz.net", "Bo", "/Sales Interns", suspended = false),
            ),
        )

        val report = service.listByOrgUnit(tenantId)

        assertEquals(listOf("/Ratnesh Test", "/Sales Interns"), report.map { it.orgUnitPath })
        assertEquals(listOf("ada@demo.econz.net", "zara@demo.econz.net"), report[0].users.map { it.primaryEmail })
        assertEquals(true, report[0].users.first { it.primaryEmail == "ada@demo.econz.net" }.suspended)
    }

    @Test
    fun `a user with no orgUnitPath is grouped under the domain root`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(directoryClient.listUsers("admin@demo.econz.net", key, "demo.econz.net")).thenReturn(
            listOf(RemoteGoogleDirectoryUser("root@demo.econz.net", "Root", orgUnitPath = null, suspended = false)),
        )

        val report = service.listByOrgUnit(tenantId)

        assertEquals("/", report.single().orgUnitPath)
    }

    @Test
    fun `refuses to call Google at all when Google Workspace is not configured for this tenant`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(null)

        assertThrows<GoogleWorkspaceConfigNotFoundException> { service.listByOrgUnit(tenantId) }
        verifyNoInteractions(directoryClient)
    }

    @Test
    fun `an empty domain is reported as no org units, not an error`() {
        whenever(configService.loadProvisioningConfig(tenantId)).thenReturn(config)
        whenever(directoryClient.listUsers("admin@demo.econz.net", key, "demo.econz.net")).thenReturn(emptyList())

        assertEquals(emptyList(), service.listByOrgUnit(tenantId))
        verify(directoryClient).listUsers("admin@demo.econz.net", key, "demo.econz.net")
    }
}
