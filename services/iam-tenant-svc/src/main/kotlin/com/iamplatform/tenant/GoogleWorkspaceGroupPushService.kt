package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import java.util.UUID

class GroupNotFoundException(groupId: UUID) : RuntimeException("No group $groupId")

data class GroupPushResult(
    val groupName: String,
    val orgUnitPath: String,
    // Whether the OU had to be created -- false means one with this name already existed in Google.
    val created: Boolean,
    // Current group members successfully moved into the OU.
    val moved: List<String>,
    // Current group members that could NOT be moved -- no matching Google account on this domain
    // (never an error on its own; reported so the admin can see who was skipped and why).
    val skipped: List<String>,
)

/**
 * The reverse of GoogleWorkspaceOuProvisioningService (added 2026-11-03): pushes an IAM group INTO
 * Google as an OU, instead of pulling a Google OU into an IAM group. For every CURRENT member of the
 * group, moves their already-existing Google account into an OU named after the group (creating that
 * OU first if it doesn't exist yet).
 *
 * Deliberately additive only: never creates a Google account, never removes anyone from the OU later
 * just because they left the IAM group -- a later push only ever adds/moves current members in, it
 * never moves anyone out. Moving a user's OU is a real structural change on Google's side (OU-scoped
 * policies like 2-Step Verification or an SSO profile apply differently afterward) -- this is exactly
 * why it's a manual, one-group-at-a-time, admin-triggered action, not automatic.
 */
@Service
class GoogleWorkspaceGroupPushService(
    private val configService: GoogleWorkspaceConfigService,
    private val directoryClient: GoogleWorkspaceDirectoryClient,
    private val groupClient: GroupClient,
    private val identityClient: IdentityClient,
    private val auditPublisher: AuditPublisher,
) {
    fun pushGroupToOrgUnit(tenantId: UUID, groupId: UUID, actingAdminId: UUID, sourceIp: String?): GroupPushResult {
        val config = configService.loadProvisioningConfig(tenantId)
            ?: throw GoogleWorkspaceConfigNotFoundException(tenantId)
        val group = groupClient.listGroups(tenantId).find { it.id == groupId }
            ?: throw GroupNotFoundException(groupId)

        val ou = directoryClient.ensureOrgUnit(config.adminEmail, config.serviceAccountKey, group.name)

        val members = identityClient.listUsers(tenantId).filter { it.groupId == groupId }
        val moved = mutableListOf<String>()
        val skipped = mutableListOf<String>()
        for (member in members) {
            if (!config.manages(member.email)) {
                skipped += member.email
                continue
            }
            val applied = directoryClient.moveToOrgUnit(config.adminEmail, config.serviceAccountKey, member.email, ou.orgUnitPath)
            if (applied) moved += member.email else skipped += member.email
        }

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.ADMIN,
                actorId = actingAdminId.toString(),
                action = "google_workspace.group_pushed_to_ou_by_admin",
                result = AuditResult.SUCCESS,
                reason = "group=${group.name}; orgUnit=${ou.orgUnitPath}; ouCreated=${ou.created}; moved=${moved.size}; skipped=${skipped.size}",
                sourceIp = sourceIp,
            ),
        )

        return GroupPushResult(group.name, ou.orgUnitPath, ou.created, moved, skipped)
    }

    /**
     * Best-effort, fire-and-forget hook called right after a user is ADDED to a group in IAM (see
     * GroupController.assignGroup) -- if this tenant has Google Workspace configured and the user's
     * email is on that domain, moves them into a Google OU matching the group's name (creating it
     * first if needed), same mechanics as pushGroupToOrgUnit, just for the one person who just joined.
     *
     * NEVER throws: a Google-side problem here must not fail the IAM group assignment that already
     * succeeded -- same "platform-side success is never undone by a downstream failure" rule as
     * suspend/reactivate and provisioning elsewhere. Silently does nothing if Google Workspace isn't
     * configured for this tenant, or the email isn't on the configured domain. Still audited either
     * way (as SYSTEM, like google_workspace_user.provisioned) so a failure is at least visible to an
     * admin who goes looking, even though nothing surfaces in the UI at the moment it happens.
     */
    fun onMemberAssigned(tenantId: UUID, groupId: UUID, userEmail: String?) {
        if (userEmail == null) return
        // Wraps EVERYTHING, not just the Google calls: a transient failure reaching identity-svc or
        // config here must not fail the IAM group assignment that already succeeded, either -- the
        // "never throws" contract this method promises its caller.
        try {
            val config = configService.loadProvisioningConfig(tenantId) ?: return
            if (!config.manages(userEmail)) return
            val group = groupClient.listGroups(tenantId).find { it.id == groupId } ?: return

            val ou = directoryClient.ensureOrgUnit(config.adminEmail, config.serviceAccountKey, group.name)
            directoryClient.moveToOrgUnit(config.adminEmail, config.serviceAccountKey, userEmail, ou.orgUnitPath)

            auditPublisher.publish(
                AuditEvent(
                    correlationId = CorrelationId.get(),
                    tenantId = tenantId,
                    actorType = ActorType.SYSTEM,
                    actorId = "iam-tenant-svc",
                    action = "google_workspace.member_auto_pushed_to_ou",
                    result = AuditResult.SUCCESS,
                    reason = "user=$userEmail; group=${group.name}",
                ),
            )
        } catch (ex: Exception) {
            auditPublisher.publish(
                AuditEvent(
                    correlationId = CorrelationId.get(),
                    tenantId = tenantId,
                    actorType = ActorType.SYSTEM,
                    actorId = "iam-tenant-svc",
                    action = "google_workspace.member_auto_pushed_to_ou",
                    result = AuditResult.FAILURE,
                    reason = "user=$userEmail; ${ex.message}",
                ),
            )
        }
    }

    /**
     * Deletes the OU matching this group's name, admin-triggered from the Groups page. Google itself
     * refuses to delete an OU that still has users or child OUs in it -- that failure surfaces as a
     * normal exception (mapped to a clear error in the UI), not swallowed. Returns false when there
     * was no such OU to begin with (not an error -- nothing to clean up).
     */
    fun deleteOrgUnitForGroup(tenantId: UUID, groupId: UUID, actingAdminId: UUID, sourceIp: String?): Boolean {
        val config = configService.loadProvisioningConfig(tenantId)
            ?: throw GoogleWorkspaceConfigNotFoundException(tenantId)
        val group = groupClient.listGroups(tenantId).find { it.id == groupId }
            ?: throw GroupNotFoundException(groupId)

        val deleted = directoryClient.deleteOrgUnit(config.adminEmail, config.serviceAccountKey, group.name)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.ADMIN,
                actorId = actingAdminId.toString(),
                action = "google_workspace.group_ou_deleted_by_admin",
                result = AuditResult.SUCCESS,
                reason = "group=${group.name}; existed=$deleted",
                sourceIp = sourceIp,
            ),
        )

        return deleted
    }
}
