package com.iamplatform.oidc

import com.iamplatform.oidc.client.IdentityClient
import com.iamplatform.oidc.client.RemoteOidcClient
import com.iamplatform.oidc.client.SessionClient
import com.iamplatform.oidc.client.TenantClient
import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import java.net.URLEncoder
import java.util.UUID

data class TokenIssuance(val accessToken: String, val idToken: String, val expiresIn: Long)
data class UserInfoResult(val sub: UUID, val email: String, val tenantId: UUID)

/**
 * Everything here is a thin wrapper: the real login decision is made once,
 * in iam-auth-svc's AuthenticationEngine (AP-1) -- this service never
 * checks a password or evaluates policy itself. As of Service 13
 * (iam-login-portal), it doesn't even call iam-auth-svc directly anymore --
 * the portal does that, and hands this service a validated session token
 * instead (see docs/specs/iam-login-portal-SPEC.md Section 0).
 */
@Service
class OidcService(
    private val tenantClient: TenantClient,
    private val sessionClient: SessionClient,
    private val identityClient: IdentityClient,
    private val codeStore: AuthorizationCodeStore,
    private val linkStore: AccessTokenLinkStore,
    private val tokenService: TokenService,
    private val auditPublisher: AuditPublisher,
    private val properties: OidcProperties,
) {

    fun validateAuthorizationRequest(clientId: UUID, redirectUri: String, responseType: String): RemoteOidcClient {
        if (responseType != "code") {
            throw InvalidAuthorizeRequestException("unsupported_response_type: only 'code' is supported")
        }
        val client = tenantClient.findClient(clientId)
            ?: throw InvalidAuthorizeRequestException("unknown client_id")
        if (redirectUri !in client.redirectUris) {
            throw InvalidAuthorizeRequestException("redirect_uri is not registered for this client")
        }
        return client
    }

    /** GET /authorize's success case: where to send the browser to actually log in. */
    fun buildLoginRedirect(clientId: UUID, redirectUri: String, scope: String, state: String): String {
        val client = validateAuthorizationRequest(clientId, redirectUri, "code")
        val tenant = tenantClient.findTenant(client.tenantId)
            ?: throw InvalidAuthorizeRequestException("tenant for this client no longer exists")

        val query = "client_id=$clientId" +
            "&redirect_uri=${encode(redirectUri)}" +
            "&scope=${encode(scope)}" +
            "&state=${encode(state)}"

        return if (properties.loginPortalBaseUrl.contains("{subdomain}")) {
            val host = properties.loginPortalBaseUrl.replace("{subdomain}", tenant.subdomain)
            "$host/login?$query"
        } else {
            // Local dev fallback -- no wildcard DNS for a real subdomain
            // host, so the portal resolves the tenant from this query param
            // instead (docs/specs/iam-login-portal-SPEC.md Section 3).
            "${properties.loginPortalBaseUrl}/login?$query&tenant=${encode(tenant.subdomain)}"
        }
    }

    /**
     * POST /authorize/complete: iam-login-portal already drove the actual
     * login against iam-auth-svc and holds a validated session token. This
     * re-validates client_id/redirect_uri (defense in depth -- doesn't trust
     * that GET /authorize's earlier validation still applies to this exact
     * request), confirms the session is real and belongs to this client's
     * tenant, and mints a single-use authorization code exactly as before.
     * Returns the full URL the portal should redirect the browser to.
     */
    fun completeAuthorization(sessionToken: String, clientId: UUID, redirectUri: String, scope: String, state: String): String {
        val client = try {
            validateAuthorizationRequest(clientId, redirectUri, "code")
        } catch (ex: InvalidAuthorizeRequestException) {
            throw AuthorizeCompleteException(ex.message ?: "invalid request")
        }

        val session = sessionClient.find(sessionToken)
            ?: throw SessionInvalidException("session token unknown or expired")
        if (session.tenantId != client.tenantId) {
            throw SessionInvalidException("session does not belong to this client's tenant")
        }
        val user = identityClient.findUser(session.userId)
            ?: throw SessionInvalidException("user for this session no longer exists")

        // Signing in is not the same as being allowed to use THIS app: the user's
        // group must have access to it (admins: any app of their organization).
        val access = tenantClient.checkAppAccess("oidc", clientId, sessionToken)
        if (!access.allowed) {
            auditPublisher.publish(
                AuditEvent(
                    correlationId = CorrelationId.get(),
                    tenantId = client.tenantId,
                    actorType = ActorType.USER,
                    actorId = session.userId.toString(),
                    action = "oidc.access_denied",
                    result = AuditResult.DENIED,
                    reason = "clientId=$clientId; ${access.reason ?: "no access"}",
                ),
            )
            throw AppAccessDeniedException(access.reason ?: "no access to this app")
        }

        val code = codeStore.issue(
            AuthorizationCodeData(
                clientId = clientId,
                tenantId = client.tenantId,
                userId = session.userId,
                email = user.email,
                redirectUri = redirectUri,
                scope = scope,
                sessionToken = sessionToken,
            ),
        )

        return redirectUri + (if (redirectUri.contains("?")) "&" else "?") + "code=$code&state=${encode(state)}"
    }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")

    fun exchangeToken(grantType: String, code: String, redirectUri: String, clientId: UUID, clientSecret: String): TokenIssuance {
        if (grantType != "authorization_code") {
            throw InvalidGrantException("unsupported grant_type")
        }

        val data = codeStore.redeem(code) ?: throw InvalidGrantException("code is invalid, expired, or already used")
        if (data.clientId != clientId || data.redirectUri != redirectUri) {
            throw InvalidGrantException("code was not issued to this client_id/redirect_uri")
        }

        val secretCheck = tenantClient.verifySecret(clientId, clientSecret)
        if (!secretCheck.valid) {
            throw InvalidClientException("invalid client_id or client_secret")
        }

        val idToken = tokenService.issueIdToken(
            properties.issuer, data.clientId, data.userId, data.tenantId, data.email, properties.idTokenTtl,
        )
        val accessToken = tokenService.issueAccessToken(
            properties.issuer, data.userId, data.tenantId, data.email, data.scope, properties.accessTokenTtl,
        )
        linkStore.link(accessToken, data.sessionToken, properties.accessTokenTtl)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = data.tenantId,
                actorType = ActorType.USER,
                actorId = data.userId.toString(),
                action = "oidc.token_issued",
                result = AuditResult.SUCCESS,
                reason = "clientId=${data.clientId}",
            ),
        )

        return TokenIssuance(accessToken, idToken, properties.accessTokenTtl.seconds)
    }

    fun userInfo(accessToken: String): UserInfoResult {
        val claims = tokenService.verifyAndParse(accessToken)
        val sessionToken = linkStore.sessionTokenFor(accessToken)
            ?: throw InvalidTokenException("access token not recognized")

        // The AP-2 tie-in: a session iam-enforcement-svc killed mid-flight
        // invalidates this access token immediately, not just at its own
        // separate JWT expiry.
        sessionClient.find(sessionToken) ?: throw InvalidTokenException("session no longer valid")

        return UserInfoResult(
            sub = UUID.fromString(claims.subject),
            email = claims.getStringClaim("email"),
            tenantId = UUID.fromString(claims.getStringClaim("tenant_id")),
        )
    }

    /**
     * Internal-only (see InternalController) -- resolves the access token to
     * its underlying platform session token via [linkStore], server-side
     * only, and terminates that session. The caller (iam-enforcement-svc's
     * gateway cookie-login path) never sees the raw session token itself,
     * same protection [AccessTokenLinkStore] already documents for
     * /userinfo. Returns false, not an error, if the access token is already
     * unknown/expired -- terminating something already gone is a no-op, not
     * a failure.
     */
    fun terminateByAccessToken(accessToken: String, reason: String): Boolean {
        val sessionToken = linkStore.sessionTokenFor(accessToken) ?: return false
        sessionClient.terminate(sessionToken, reason)
        return true
    }
}
