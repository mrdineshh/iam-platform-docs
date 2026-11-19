package com.iamplatform.auth

import com.iamplatform.auth.client.DeviceClient
import com.iamplatform.auth.client.EnsurePendingResult
import com.iamplatform.auth.client.GeoClient
import com.iamplatform.auth.client.IdentityClient
import com.iamplatform.auth.client.PolicyClient
import com.iamplatform.auth.client.RemoteDeviceStatus
import com.iamplatform.auth.client.RemotePushResult
import com.iamplatform.auth.client.RemoteUserRole
import com.iamplatform.auth.client.RemoteUserStatus
import com.iamplatform.auth.client.GeoResolution
import com.iamplatform.auth.client.LoginDeviceCheckRequest
import com.iamplatform.auth.client.SessionClient
import com.iamplatform.auth.client.SessionContext
import com.iamplatform.auth.client.TenantClient
import com.iamplatform.auth.client.VerifyDeviceProofRequest
import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import io.github.resilience4j.circuitbreaker.CallNotPermittedException
import org.springframework.stereotype.Service
import org.springframework.web.client.HttpClientErrorException
import org.springframework.web.client.ResourceAccessException
import java.util.UUID

// The only codes iam-tenant-svc's device check may answer with; anything else is treated as DEVICE_REQUIRED.
private val DEVICE_RULE_CODES = listOf(AuthErrorCode.DEVICE_REQUIRED, AuthErrorCode.DEVICE_NOT_APPROVED, AuthErrorCode.DEVICE_NON_COMPLIANT)

private data class PolicyDecision(
    val allowed: Boolean,
    val reason: String?,
    val scope: String?,
    val mfaRequired: Boolean = true,
    val totpReenrollEveryLogin: Boolean = false,
)

/**
 * The single AuthenticationEngine (AP-1) -- every login decision, whatever
 * the future upstream source (password here; Google Workspace in Service 8),
 * is made here and nowhere else. Orchestrates identity -> geo + policy ->
 * session, all Resilience4j-wrapped, under one correlation ID.
 */
@Service
class AuthService(
    private val identityClient: IdentityClient,
    private val geoClient: GeoClient,
    private val policyClient: PolicyClient,
    private val deviceClient: DeviceClient,
    private val sessionClient: SessionClient,
    private val auditPublisher: AuditPublisher,
    private val tenantClient: TenantClient,
) {

    /**
     * @param enforceDeviceRule false ONLY for the device-enrollment sign-in, which arrives on the service-to-service-only
     * route (InternalOnlyFilter) and whose session the portal never hands to the browser. A new laptop has to sign in once to
     * register itself, so the tenant's "authorised laptop to sign in" rule cannot apply to that one step. The public /login
     * route always enforces it, and this is a parameter, not a request field, so no caller can switch it off.
     */
    fun login(request: LoginRequest, enforceDeviceRule: Boolean = true): LoginResponse {
        val correlationId = CorrelationId.get()

        val verified = identityClient.verifyPassword(request.tenantId, request.email, request.password)
        if (verified.locked) {
            audit(request.tenantId, request.email, "auth.login_denied", AuditResult.DENIED, "account locked", request.sourceIp)
            throw LoginDeniedException("account locked", AuthErrorCode.ACCOUNT_LOCKED)
        }
        if (!verified.valid) {
            audit(request.tenantId, request.email, "auth.login_failure", AuditResult.FAILURE, "invalid credentials", request.sourceIp)
            throw InvalidCredentialsException()
        }
        val userId = verified.userId!!
        if (verified.status != RemoteUserStatus.ACTIVE) {
            audit(request.tenantId, userId.toString(), "auth.login_denied", AuditResult.DENIED, "account suspended", request.sourceIp)
            throw LoginDeniedException("account suspended", AuthErrorCode.ACCOUNT_SUSPENDED)
        }

        val (country, decision, geo) = resolvePolicy(request.tenantId, userId, verified.groupId, request.sourceIp)
        if (!decision.allowed) {
            audit(
                request.tenantId, userId.toString(), "auth.login_denied", AuditResult.DENIED,
                decision.reason, request.sourceIp, geo = country, policyScopeApplied = decision.scope,
            )
            val errorCode = when (decision.reason) {
                "location could not be verified" -> AuthErrorCode.LOCATION_UNVERIFIED
                "policy could not be evaluated" -> AuthErrorCode.POLICY_UNAVAILABLE
                else -> AuthErrorCode.POLICY_DENIED
            }
            throw LoginDeniedException(decision.reason ?: "denied by policy", errorCode)
        }

        // Second factor (Service 9, AP-1: a step of this same orchestrated
        // login, not a separate MFA endpoint). Whether it's required at all
        // is now a merged policy attribute (tenant/group/user, AP-4) instead
        // of the earlier hardcoded "always required" -- see
        // iam-policy-svc's mfaRequired, default true (never fail open: no
        // policy configured means MFA stays required, not skipped).
        if (decision.mfaRequired) {
            // Self-service first-login enrollment: no code submitted yet AND
            // no ACTIVE device exists -- rather than attempting a push (which
            // would just fail with "no push-capable device"), hand the user
            // their own QR right now instead of making an admin relay it.
            // Safe to call on every no-code attempt: once a device is
            // ACTIVE, ensurePending always reports alreadyActive and falls
            // through to the normal push path below.
            if (request.totpCode == null) {
                val pending = if (decision.totpReenrollEveryLogin) {
                    deviceClient.resetAndEnroll(request.tenantId, userId).let {
                        EnsurePendingResult(alreadyActive = false, it.deviceId, it.totpSecret, it.provisioningUri)
                    }
                } else {
                    orNull { deviceClient.ensurePending(request.tenantId, userId) }
                }
                if (pending != null && !pending.alreadyActive) {
                    audit(
                        request.tenantId, userId.toString(), "auth.enrollment_offered", AuditResult.SUCCESS,
                        null, request.sourceIp, geo = country, policyScopeApplied = decision.scope,
                    )
                    return LoginResponse(
                        enrollmentRequired = true,
                        totpSecret = pending.totpSecret,
                        provisioningUri = pending.provisioningUri,
                    )
                }
            }

            val mfaDenial = verifySecondFactor(request, userId)
            if (mfaDenial != null) {
                audit(
                    request.tenantId, userId.toString(), "auth.login_denied", AuditResult.DENIED,
                    mfaDenial.first, request.sourceIp, geo = country, policyScopeApplied = decision.scope,
                )
                throw LoginDeniedException(mfaDenial.first, mfaDenial.second)
            }
        }

        // Not caught -- an issuance failure propagates to GlobalExceptionHandler
        // as a 503 (BUILD_PLAN.md Service 7 TEST GATE: "login fails cleanly
        // with a 503, not a hang or a partial state").
        val context = SessionContext(request.userAgent, country, geo?.region, geo?.city)
        // Device-bound sign-in. Looked at only when the caller sent a proof; otherwise this line changes nothing.
        val deviceId = request.deviceProof?.let { verifiedDeviceId(request.tenantId, request.sourceIp, userId, it, country) }
        val role = verified.role ?: RemoteUserRole.USER
        if (enforceDeviceRule) {
            enforceTenantDeviceRule(request.tenantId, request.sourceIp, userId, role, deviceId, country, decision.scope)
        } else {
            audit(request.tenantId, userId.toString(), "auth.login.enrollment_signin", AuditResult.SUCCESS, null, request.sourceIp, geo = country)
        }
        val session = if (deviceId != null) {
            sessionClient.issueForDevice(request.tenantId, userId, request.sourceIp, idempotencyKey = correlationId, context = context, deviceId = deviceId)
        } else {
            sessionClient.issue(request.tenantId, userId, request.sourceIp, idempotencyKey = correlationId, context = context)
        }

        // Where and on what the person signed in, so the audit trail shows it alongside the IP.
        val place = listOfNotNull(geo?.city, geo?.region, country).joinToString(", ")
        val where = listOf(place, request.userAgent?.take(120).orEmpty()).filter { it.isNotBlank() }.joinToString(" | ").ifBlank { null }
        audit(request.tenantId, userId.toString(), "auth.login_success", AuditResult.SUCCESS, where, request.sourceIp, geo = country)

        return LoginResponse(session.token, session.sessionId, session.expiresAt, role = role.name)
    }

    /**
     * Platform-level "authorised laptop" rule, decided by iam-tenant-svc (which owns the tenant's switch and the device
     * state) and enforced here, before any session exists. Fails CLOSED: if the answer cannot be had, the sign-in is
     * refused with its own code, never let through (AP-3: no path where a session is issued without the platform deciding).
     */
    private fun enforceTenantDeviceRule(tenantId: UUID, sourceIp: String, userId: UUID, role: RemoteUserRole, deviceId: UUID?, country: String?, scope: String?) {
        val answer = try {
            tenantClient.checkLoginDevice(LoginDeviceCheckRequest(tenantId, userId, role.name, deviceId?.toString()))
        } catch (ex: Exception) {
            audit(
                tenantId, userId.toString(), "auth.login_denied", AuditResult.DENIED,
                "device rule could not be checked", sourceIp, geo = country, policyScopeApplied = scope,
            )
            throw LoginDeniedException("device rule could not be checked", AuthErrorCode.DEVICE_CHECK_UNAVAILABLE)
        }
        if (answer.allowed) return
        val code = DEVICE_RULE_CODES.firstOrNull { it.name == answer.code } ?: AuthErrorCode.DEVICE_REQUIRED
        val reason = "device not authorised: ${code.name.lowercase()}${answer.detail?.let { " ($it)" } ?: ""}"
        audit(tenantId, userId.toString(), "auth.login_denied", AuditResult.DENIED, reason, sourceIp, geo = country, policyScopeApplied = scope)
        throw LoginDeniedException("You are not authorised to sign in from this device.", code)
    }

    /**
     * Added for iam-login-portal's multi-step UI -- lets the frontend find
     * out, after password but before asking for a code, whether this user
     * needs a code at all (mfaRequired=false -> submit /login directly, no
     * third screen) or needs to enroll a device for the first time
     * (enrollmentRequired=true -> show this QR) -- all WITHOUT touching
     * /login's push path, which blocks for up to 60s and would otherwise
     * fire an unwanted push notification just from clicking "Next".
     * Never issues a session itself; same password/account/policy checks as
     * login() (duplicated, not shared statefully -- this is intentionally a
     * read-only preflight, not a side-door around AP-1's single
     * session-issuing engine).
     */
    fun precheck(request: PrecheckRequest, enforceDeviceRule: Boolean = true): PrecheckResponse {
        val verified = identityClient.verifyPassword(request.tenantId, request.email, request.password)
        if (verified.locked) {
            audit(request.tenantId, request.email, "auth.login_denied", AuditResult.DENIED, "account locked", request.sourceIp)
            throw LoginDeniedException("account locked", AuthErrorCode.ACCOUNT_LOCKED)
        }
        if (!verified.valid) {
            audit(request.tenantId, request.email, "auth.login_failure", AuditResult.FAILURE, "invalid credentials", request.sourceIp)
            throw InvalidCredentialsException()
        }
        val userId = verified.userId!!
        if (verified.status != RemoteUserStatus.ACTIVE) {
            audit(request.tenantId, userId.toString(), "auth.login_denied", AuditResult.DENIED, "account suspended", request.sourceIp)
            throw LoginDeniedException("account suspended", AuthErrorCode.ACCOUNT_SUSPENDED)
        }

        val (country, decision, _) = resolvePolicy(request.tenantId, userId, verified.groupId, request.sourceIp)
        if (!decision.allowed) {
            audit(
                request.tenantId, userId.toString(), "auth.login_denied", AuditResult.DENIED,
                decision.reason, request.sourceIp, geo = country, policyScopeApplied = decision.scope,
            )
            val errorCode = when (decision.reason) {
                "location could not be verified" -> AuthErrorCode.LOCATION_UNVERIFIED
                "policy could not be evaluated" -> AuthErrorCode.POLICY_UNAVAILABLE
                else -> AuthErrorCode.POLICY_DENIED
            }
            throw LoginDeniedException(decision.reason ?: "denied by policy", errorCode)
        }

        // The platform "authorised laptop to sign in" rule, asked here as well so the person hears "you are not authorised
        // to sign in from this device" right after the password -- BEFORE a code is requested or a push is sent to their
        // phone. login() asks again and that is the decision that counts; this one is only the early answer.
        // Same exemption as login(): false only for the enrollment sign-in, on the service-to-service-only route.
        if (enforceDeviceRule) {
            val proven = request.deviceProof?.let { verifiedDeviceId(request.tenantId, request.sourceIp, userId, it, country) }
            enforceTenantDeviceRule(request.tenantId, request.sourceIp, userId, verified.role ?: RemoteUserRole.USER, proven, country, decision.scope)
        }

        if (!decision.mfaRequired) {
            return PrecheckResponse(mfaRequired = false, enrollmentRequired = false)
        }

        val pending = if (decision.totpReenrollEveryLogin) {
            deviceClient.resetAndEnroll(request.tenantId, userId).let {
                EnsurePendingResult(alreadyActive = false, it.deviceId, it.totpSecret, it.provisioningUri)
            }
        } else {
            orNull { deviceClient.ensurePending(request.tenantId, userId) }
        }
        return if (pending != null && !pending.alreadyActive) {
            PrecheckResponse(
                mfaRequired = true,
                enrollmentRequired = true,
                totpSecret = pending.totpSecret,
                provisioningUri = pending.provisioningUri,
            )
        } else {
            PrecheckResponse(mfaRequired = true, enrollmentRequired = false)
        }
    }

    fun logout(token: String) {
        sessionClient.terminate(token, reason = "logout")
    }

    /** Shared by login() and precheck() -- resolves geo + merged policy, including mfaRequired. */
    private fun resolvePolicy(tenantId: UUID, userId: UUID, groupId: UUID?, sourceIp: String): Triple<String?, PolicyDecision, GeoResolution?> {
        // Section 4.6: iam-geo-svc unreachable -> unresolved/high-risk, never
        // an automatic pass. Caught here, not left to propagate, so an
        // infra blip on the geo lookup degrades to a denial, not a 503.
        val geo = orNull { geoClient.resolve(sourceIp) }
        val country = geo?.takeIf { it.resolved }?.country

        val decision = if (country == null) {
            PolicyDecision(allowed = false, reason = "location could not be verified", scope = null)
        } else {
            val evaluation = orNull { policyClient.evaluate(tenantId, userId, groupId, country, sourceIp) }
            if (evaluation == null) {
                PolicyDecision(allowed = false, reason = "policy could not be evaluated", scope = null)
            } else {
                PolicyDecision(
                    evaluation.allowed, evaluation.reason, evaluation.policyScopeApplied,
                    evaluation.mfaRequired, evaluation.totpReenrollEveryLogin,
                )
            }
        }
        return Triple(country, decision, geo)
    }

    /** Null return means the second factor passed; a non-null pair is (reason, errorCode) for the denial. */
    /**
     * The device the proof vouches for, or null. NEVER throws and never blocks the sign-in: the person is already
     * authenticated; a missing, wrong or unverifiable proof only means the session carries no device (so apps that
     * require a trusted device will refuse it, and everything else is unaffected).
     */
    private fun verifiedDeviceId(tenantId: UUID, sourceIp: String, userId: UUID, proof: DeviceProof, country: String?): UUID? {
        val verified = try {
            tenantClient.verifyDeviceProof(proof.challengeId, VerifyDeviceProofRequest(userId, proof.deviceId, proof.signature, proof.origin))
        } catch (ex: Exception) {
            null
        }
        if (verified == null) {
            audit(tenantId, userId.toString(), "auth.device_proof_not_accepted", AuditResult.DENIED, "device proof missing, invalid or unverifiable", sourceIp, geo = country)
        }
        return verified?.deviceId
    }

    private fun verifySecondFactor(request: LoginRequest, userId: UUID): Pair<String, AuthErrorCode>? =
        if (request.totpCode != null) {
            val result = try {
                deviceClient.verifyTotp(request.tenantId, userId, request.totpCode)
            } catch (ex: HttpClientErrorException.NotFound) {
                return "no second factor enrolled" to AuthErrorCode.NO_SECOND_FACTOR_ENROLLED
            } catch (ex: CallNotPermittedException) {
                return "second factor could not be verified" to AuthErrorCode.SECOND_FACTOR_UNAVAILABLE
            } catch (ex: ResourceAccessException) {
                return "second factor could not be verified" to AuthErrorCode.SECOND_FACTOR_UNAVAILABLE
            }
            when {
                result.valid -> null
                result.status == RemoteDeviceStatus.LOCKED -> "second factor locked" to AuthErrorCode.TOTP_LOCKED
                else -> "invalid second factor code" to AuthErrorCode.TOTP_INVALID
            }
        } else {
            val result = try {
                deviceClient.sendPush(request.tenantId, userId)
            } catch (ex: HttpClientErrorException.NotFound) {
                return "no push-capable second factor enrolled" to AuthErrorCode.NO_PUSH_DEVICE_ENROLLED
            } catch (ex: CallNotPermittedException) {
                return "second factor unavailable" to AuthErrorCode.SECOND_FACTOR_UNAVAILABLE
            } catch (ex: ResourceAccessException) {
                return "second factor unavailable" to AuthErrorCode.SECOND_FACTOR_UNAVAILABLE
            }
            when (result.result) {
                RemotePushResult.APPROVED -> null
                RemotePushResult.DENIED -> "second factor denied" to AuthErrorCode.PUSH_DENIED
                RemotePushResult.TIMEOUT -> "second factor timed out" to AuthErrorCode.PUSH_TIMEOUT
            }
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
        tenantId: UUID,
        actorId: String,
        action: String,
        result: AuditResult,
        reason: String?,
        sourceIp: String?,
        geo: String? = null,
        policyScopeApplied: String? = null,
    ) {
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.USER,
                actorId = actorId,
                action = action,
                result = result,
                reason = reason,
                sourceIp = sourceIp,
                geo = geo,
                policyScopeApplied = policyScopeApplied,
            ),
        )
    }
}
