package com.iamplatform.tenant

import org.springframework.stereotype.Service
import java.util.UUID

/** One OU and the real Google users currently in it -- "/" covers anyone at the domain root. */
data class OrgUnitReport(val orgUnitPath: String, val users: List<RemoteGoogleDirectoryUser>)

/**
 * Read-only "what does my Google Workspace actually look like" view for the admin console's
 * Organizational units page (added 2026-10-30). Groups every domain user by their current OU,
 * re-fetched live on every call -- nothing is ever written to Google or stored in IAM by this class.
 * Deliberately separate from GoogleWorkspaceConfigService (settings) and the provisioning/lifecycle
 * code (which still decides where a NEW account is created, e.g. the tenant's configured OU) -- this
 * service only reads and reports, and touches neither.
 *
 * An OU with no users in it will not appear here, since there is nothing to group under it -- this is
 * a report over users, not a separate call to Google's org-unit catalog (which would need an
 * additional permission this deliberately avoids asking for).
 */
@Service
class GoogleWorkspaceDirectoryReportService(
    private val configService: GoogleWorkspaceConfigService,
    private val directoryClient: GoogleWorkspaceDirectoryClient,
) {
    fun listByOrgUnit(tenantId: UUID): List<OrgUnitReport> {
        val config = configService.loadProvisioningConfig(tenantId)
            ?: throw GoogleWorkspaceConfigNotFoundException(tenantId)
        val users = directoryClient.listUsers(config.adminEmail, config.serviceAccountKey, config.domain)
        return users
            .groupBy { it.orgUnitPath ?: "/" }
            .toSortedMap()
            .map { (ou, members) -> OrgUnitReport(ou, members.sortedBy { it.primaryEmail }) }
    }
}
