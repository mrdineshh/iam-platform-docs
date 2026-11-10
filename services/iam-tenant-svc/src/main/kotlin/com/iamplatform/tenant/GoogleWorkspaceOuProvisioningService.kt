package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import java.security.SecureRandom
import java.util.UUID

data class OuProvisionResult(
    val orgUnitPath: String,
    val groupName: String,
    // Already existed in IAM -- their group was set/updated to match this OU, nothing else touched.
    val matched: List<String>,
    // Didn't exist in IAM -- a new account was created, a first 2FA device enrolled, pushed to every
    // SCIM app, added to the group, and (if this list) successfully emailed their sign-in details.
    val created: List<String>,
    // Account WAS created (same as above), but sending the email itself failed -- these people cannot
    // sign in yet because nobody has their temporary password. Handle these manually.
    val createdButEmailFailed: List<String>,
)

/**
 * The write side of the Organizational units page's "Sync into IAM group" action (added 2026-10-31,
 * see docs/DECISIONS.md): for ONE Google OU at a time --
 *   - existing IAM users (matched by email) get their group set to match the OU;
 *   - anyone in the OU with no IAM account gets one created (role USER, no new Google Workspace
 *     account -- they already have one, that's how they got here), a first 2FA device enrolled, and
 *     the matching app accounts provisioned (same as the normal "+ Add user" flow), then emailed their
 *     address, a one-time temporary password, and a QR code for their authenticator app.
 * Deliberately scoped to a single OU per call -- see OrganizationalUnitsPage.tsx and the admin console
 * conversation that led here: the explicit ask was "only Ratnesh Test", not "sync my whole domain".
 */
@Service
class GoogleWorkspaceOuProvisioningService(
    private val configService: GoogleWorkspaceConfigService,
    private val directoryClient: GoogleWorkspaceDirectoryClient,
    private val identityClient: IdentityClient,
    private val deviceClient: DeviceClient,
    private val groupClient: GroupClient,
    private val provisioningService: ProvisioningService,
    private val auditPublisher: AuditPublisher,
) {
    private val secureRandom = SecureRandom()

    fun syncOrgUnit(tenantId: UUID, orgUnitPath: String, actingAdminId: UUID, sourceIp: String?): OuProvisionResult {
        val config = configService.loadProvisioningConfig(tenantId)
            ?: throw GoogleWorkspaceConfigNotFoundException(tenantId)

        val ouUsers = directoryClient.listUsers(config.adminEmail, config.serviceAccountKey, config.domain)
            .filter { (it.orgUnitPath ?: "/") == orgUnitPath }

        val groupName = if (orgUnitPath == "/") "Root" else orgUnitPath.removePrefix("/")
        val group = groupClient.listGroups(tenantId).find { it.name.equals(groupName, ignoreCase = true) }
            ?: groupClient.createGroup(tenantId, groupName)

        val iamUsersByEmail = identityClient.listUsers(tenantId).associateBy { it.email.lowercase() }

        val matched = mutableListOf<String>()
        val created = mutableListOf<String>()
        val createdButEmailFailed = mutableListOf<String>()

        for (googleUser in ouUsers) {
            val existing = iamUsersByEmail[googleUser.primaryEmail.lowercase()]
            if (existing != null) {
                groupClient.assignGroup(existing.id, group.id)
                matched += googleUser.primaryEmail
                continue
            }

            val tempPassword = generateTempPassword()
            val createdUser = identityClient.createUser(
                CreateRemoteUserRequest(
                    tenantId = tenantId,
                    email = googleUser.primaryEmail,
                    displayName = googleUser.fullName?.takeIf { it.isNotBlank() } ?: googleUser.primaryEmail.substringBefore('@'),
                    password = tempPassword,
                    role = RemoteUserRole.USER,
                ),
            )
            val device = deviceClient.enroll(createdUser.tenantId, createdUser.id)
            groupClient.assignGroup(createdUser.id, group.id)
            provisioningService.reconcile(
                ProvisionUser(createdUser.id, tenantId, createdUser.email, createdUser.displayName, active = true),
            )

            try {
                directoryClient.sendEmail(
                    adminEmail = config.adminEmail,
                    key = config.serviceAccountKey,
                    to = googleUser.primaryEmail,
                    subject = "Your sign-in to $groupName",
                    htmlBody = onboardingEmailHtml(createdUser.displayName, createdUser.email, tempPassword, groupName),
                    qrCodeData = device.provisioningUri,
                )
                created += googleUser.primaryEmail
            } catch (ex: GoogleProvisioningException) {
                // The account exists and works either way -- only the notification failed. Report it
                // so an admin can hand the person their password/QR another way; never roll back the
                // account creation over an email delivery problem (same "never undo platform-side
                // success over a downstream failure" rule as suspend/reactivate elsewhere).
                createdButEmailFailed += googleUser.primaryEmail
            }
        }

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.ADMIN,
                actorId = actingAdminId.toString(),
                action = "google_workspace.ou_synced_by_admin",
                result = AuditResult.SUCCESS,
                reason = "orgUnit=$orgUnitPath; group=$groupName; matched=${matched.size}; created=${created.size}; emailFailed=${createdButEmailFailed.size}",
                sourceIp = sourceIp,
            ),
        )

        return OuProvisionResult(orgUnitPath, group.name, matched, created, createdButEmailFailed)
    }

    // Guarantees every character class a password policy might require, rather than hoping a purely
    // random string happens to include one -- this runs unattended, possibly for several people in one
    // call, so a policy-rejection failure here should not be a matter of chance.
    private fun generateTempPassword(): String {
        val upper = "ABCDEFGHJKLMNPQRSTUVWXYZ"
        val lower = "abcdefghijkmnpqrstuvwxyz"
        val digits = "23456789"
        val symbols = "!@#%^&*-_="
        val all = upper + lower + digits + symbols
        val required = listOf(upper, lower, digits, symbols).map { it[secureRandom.nextInt(it.length)] }
        val rest = (1..12).map { all[secureRandom.nextInt(all.length)] }
        return (required + rest).shuffled(java.util.Random(secureRandom.nextLong())).joinToString("")
    }

    private fun onboardingEmailHtml(displayName: String, email: String, tempPassword: String, groupName: String): String = """
        <div style="font-family:Arial,sans-serif;max-width:480px;margin:0 auto;color:#111">
          <h2 style="margin:0 0 8px">Welcome, ${displayName.escapeHtml()}</h2>
          <p>An account was created for you in the IAM platform, as part of <strong>${groupName.escapeHtml()}</strong>.</p>
          <p style="margin:20px 0"><strong>Email:</strong> ${email.escapeHtml()}<br/>
          <strong>Temporary password:</strong> <code style="background:#f1f1f1;padding:2px 6px;border-radius:4px">${tempPassword.escapeHtml()}</code></p>
          <p>Scan this code with your authenticator app (Google Authenticator, Authy, etc.) when you sign in for the first time:</p>
          <p><img src="cid:qrcode" width="220" height="220" alt="2FA QR code" /></p>
          <p style="color:#666;font-size:0.85em">You'll be asked to sign in with the email and temporary password above, then confirm a 6-digit code
          from your authenticator app. Contact your administrator if you have any trouble.</p>
        </div>
    """.trimIndent()

    private fun String.escapeHtml(): String =
        replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;")
}
