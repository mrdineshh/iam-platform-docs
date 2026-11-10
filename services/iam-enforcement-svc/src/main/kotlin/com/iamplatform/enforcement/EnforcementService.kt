package com.iamplatform.enforcement

import com.iamplatform.enforcement.client.DeviceTrustClient
import com.iamplatform.enforcement.client.EvaluateResponse
import com.iamplatform.enforcement.client.GeoClient
import com.iamplatform.enforcement.client.IdentityClient
import com.iamplatform.enforcement.client.PolicyClient
import com.iamplatform.enforcement.client.RemoteSession
import com.iamplatform.enforcement.client.RemoteUserStatus
import com.iamplatform.enforcement.client.SessionClient
import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import io.github.resilience4j.circuitbreaker.CallNotPermittedException
import org.springframework.stereotype.Service
import org.springframework.web.client.ResourceAccessException
import java.util.UUID

data class GatewayCheckResult(
    val allowed: Boolean,
    val reason: String? = null,
    val country: String? = null,
    val policyScopeApplied: String? = null,
    val shouldTerminate: Boolean = false,
)

/**
 * The PEP (BUILD_PLAN.md Service 10, AP-2). Re-validates session, current
 * location, and policy fresh on every call -- independent of iam-auth-svc,
 * which only runs at login. Only session validity and the policy decision
 * are ever cached (the latter briefly, in PolicyDecisionCache); nothing
 * here assumes yesterday's decision still holds.
 */
@Service
class EnforcementService(
    private val sessionClient: SessionClient,
    private val geoClient: GeoClient,
    private val policyClient: PolicyClient,
    private val identityClient: IdentityClient,
    private val deviceTrustClient: DeviceTrustClient,
    private val policyCache: PolicyDecisionCache,
    private val auditPublisher: AuditPublisher,
) {

    fun enforce(token: String, request: EnforceRequest): EnforceResponse {
        val session = sessionClient.validate(token)
            ?: throw EnforcementDeniedException("session not found, expired, or terminated")

        // Added 2026-10-26: session validity alone isn't enough -- a
        // deleted/suspended user's existing session was otherwise still
        // "valid" (Valkey has no idea identity_db changed) and kept
        // passing every check below indefinitely. Found live: a deleted
        // user's pre-existing session still returned allowed=true until
        // this check was added. Any failure here terminates the session,
        // same as an actual policy violation -- there's no legitimate
        // reason for a session to outlive the account it belongs to.
        val user = orNull { identityClient.findUser(session.userId) }
        if (user == null || user.status != RemoteUserStatus.ACTIVE) {
            sessionClient.terminate(token, reason = "user no longer exists or is suspended")
            audit(session, request.sourceIp, "user no longer exists or is suspended", terminate = true)
            throw EnforcementDeniedException("user no longer exists or is suspended")
        }

        requireDeviceTrustIfClaimed(session, token, request.sourceIp)

        // Section 4.6: never fail open. An unresolved location is
        // high-risk/unknown, not a free pass -- same rule iam-auth-svc
        // applies at login, just re-checked here on every later request.
        val geo = orNull { geoClient.resolve(request.sourceIp) }
        val country = geo?.takeIf { it.resolved }?.country
        if (country == null) {
            audit(session, request.sourceIp, "location could not be verified", terminate = false)
            throw EnforcementDeniedException("location could not be verified")
        }

        val decision = policyCache.get(session.tenantId, session.userId, country) ?: evaluateAndCache(session, request.sourceIp, country)

        if (!decision.allowed) {
            sessionClient.terminate(token, reason = decision.reason ?: "policy violation")
            audit(
                session, request.sourceIp, decision.reason ?: "denied by policy", terminate = true,
                policyScopeApplied = decision.policyScopeApplied, country = country,
            )
            throw EnforcementDeniedException(decision.reason ?: "denied by policy")
        }

        return EnforceResponse(allowed = true, sessionId = session.sessionId, tenantId = session.tenantId, userId = session.userId, country = country)
    }

    // Devices in any of these states must never satisfy a continuous device-trust check (Endpoint
    // Device Trust spec Section 6.2's access-implication column). Phase 1 scope: this is a
    // whole-session allow/deny gate, not yet the per-application pending/offline overrides the spec
    // also describes (Section 6.4, 15.3) -- those require the PEP to know which application is being
    // accessed, which this call site doesn't carry today.
    private val trustedDeviceStatuses = setOf("APPROVED")

    /**
     * Only runs when the session actually claims a device (session.deviceId is a UUID the agent
     * registered during enrollment) -- a session created before this feature existed, or one from a
     * login path that never bound a device, makes no such claim and is unaffected, exactly like
     * every other continuous check in this class only acting on evidence it actually has. Spec
     * Section 4.2: "a protected application must not trust a client-supplied device ID alone" -- this
     * is that check, re-verified against iam-tenant-svc's device registry on every request, not just
     * accepted from the session row.
     */
    private fun requireDeviceTrustIfClaimed(session: RemoteSession, token: String, sourceIp: String) {
        val deviceId = session.deviceId?.let { runCatching { UUID.fromString(it) }.getOrNull() } ?: return
        val status = orNull { deviceTrustClient.findDeviceTrustStatus(session.tenantId, deviceId) }
        if (status == null || status.lifecycleStatus !in trustedDeviceStatuses) {
            val reason = if (status == null) "device is no longer registered" else "device is ${status.lifecycleStatus.lowercase()}, not approved"
            sessionClient.terminate(token, reason = reason)
            audit(session, sourceIp, reason, terminate = true)
            throw EnforcementDeniedException(reason)
        }
    }

    private fun evaluateAndCache(session: RemoteSession, sourceIp: String, country: String): EvaluateResponse {
        val evaluated = orNull { policyClient.evaluate(session.tenantId, session.userId, country, sourceIp) }
            ?: run {
                audit(session, sourceIp, "policy could not be evaluated", terminate = false)
                throw EnforcementDeniedException("policy could not be evaluated")
            }
        policyCache.put(session.tenantId, session.userId, country, evaluated)
        return evaluated
    }

    /**
     * The gateway cookie-login path's counterpart to [enforce] -- same
     * geo/policy logic and 30s policy cache, but keyed directly off an
     * already-resolved tenantId/userId rather than a raw session token,
     * since the gateway only holds an OpenID Connect access token (see
     * GatewayOidcClient), not the platform's own opaque session token.
     * Session liveness itself is checked separately, by the caller, via a
     * call to /userinfo -- this method only ever does the *continuous*
     * location/policy re-check, matching [enforce]'s never-fail-open
     * behavior exactly. [GatewayCheckResult.shouldTerminate] mirrors
     * [enforce]'s own terminate-vs-just-deny distinction: only an actual
     * policy denial kills the session -- an unresolved location or an
     * unreachable policy service denies this one request without touching
     * the session, same precedent as [enforce].
     *
     * Known gap (not yet closed): unlike [enforce], this path does not run
     * [requireDeviceTrustIfClaimed] -- the OIDC userinfo response this is
     * keyed off doesn't carry a deviceId claim today, so there is nothing
     * to check yet. A gateway-fronted app behind this cookie-login path is
     * therefore not currently device-trust-enforced even if the signed-in
     * user has an approved device elsewhere. Closing this requires the
     * OIDC provider to carry device binding into its own session/userinfo,
     * which is separate follow-up work, not done here.
     */
    fun checkLocationAndPolicy(tenantId: UUID, userId: UUID, sourceIp: String): GatewayCheckResult {
        // Same identity-existence check as enforce() -- see its comment.
        // shouldTerminate=true here too: the caller (ProxyController) is
        // expected to kill the underlying session via the OIDC provider's
        // internal termination endpoint on this result, same as any other
        // policy violation.
        val user = orNull { identityClient.findUser(userId) }
        if (user == null || user.status != RemoteUserStatus.ACTIVE) {
            auditGateway(tenantId, userId, sourceIp, null, "user no longer exists or is suspended", terminate = true)
            return GatewayCheckResult(allowed = false, reason = "user no longer exists or is suspended", shouldTerminate = true)
        }

        val geo = orNull { geoClient.resolve(sourceIp) }
        val country = geo?.takeIf { it.resolved }?.country
        if (country == null) {
            auditGateway(tenantId, userId, sourceIp, null, "location could not be verified", terminate = false)
            return GatewayCheckResult(allowed = false, reason = "location could not be verified")
        }

        val decision = policyCache.get(tenantId, userId, country) ?: run {
            val evaluated = orNull { policyClient.evaluate(tenantId, userId, country, sourceIp) }
            if (evaluated == null) {
                auditGateway(tenantId, userId, sourceIp, country, "policy could not be evaluated", terminate = false)
                return GatewayCheckResult(allowed = false, reason = "policy could not be evaluated", country = country)
            }
            policyCache.put(tenantId, userId, country, evaluated)
            evaluated
        }

        if (!decision.allowed) {
            auditGateway(
                tenantId, userId, sourceIp, country, decision.reason ?: "denied by policy",
                terminate = true, policyScopeApplied = decision.policyScopeApplied,
            )
            return GatewayCheckResult(
                allowed = false, reason = decision.reason ?: "denied by policy",
                country = country, policyScopeApplied = decision.policyScopeApplied, shouldTerminate = true,
            )
        }

        return GatewayCheckResult(allowed = true, country = country)
    }

    private fun auditGateway(
        tenantId: UUID, userId: UUID, sourceIp: String, country: String?, reason: String,
        terminate: Boolean, policyScopeApplied: String? = null,
    ) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.USER,
                actorId = userId.toString(),
                action = if (terminate) "enforcement.violation" else "enforcement.check_denied",
                result = AuditResult.DENIED,
                reason = reason,
                sourceIp = sourceIp,
                geo = country,
                policyScopeApplied = policyScopeApplied,
            ),
        )
    }

    private fun <T> orNull(call: () -> T): T? =
        try {
            call()
        } catch (ex: CallNotPermittedException) {
            null
        } catch (ex: ResourceAccessException) {
            null
        }

    private fun audit(
        session: RemoteSession,
        currentSourceIp: String,
        reason: String,
        terminate: Boolean,
        policyScopeApplied: String? = null,
        country: String? = null,
    ) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = session.tenantId,
                actorType = ActorType.USER,
                actorId = session.userId.toString(),
                action = if (terminate) "enforcement.violation" else "enforcement.check_denied",
                result = AuditResult.DENIED,
                reason = reason,
                sourceIp = currentSourceIp,
                geo = country,
                deviceId = session.deviceId,
                policyScopeApplied = policyScopeApplied,
            ),
        )
    }
}
