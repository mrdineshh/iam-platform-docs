package com.iamplatform.enforcement

import com.iamplatform.enforcement.client.GatewayNotConfiguredException
import com.iamplatform.enforcement.client.GatewayOidcClient
import com.iamplatform.servicekit.http.resilientRestClientBuilder
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.beans.factory.annotation.Value
import org.springframework.http.HttpMethod
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestClient
import org.springframework.web.client.RestClientResponseException
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.UUID

/** Who the gateway has already confirmed is making this request -- handed to the upstream as a trusted header, never trusted from the incoming request itself. */
data class GatewayIdentity(val userId: UUID, val tenantId: UUID, val email: String? = null)

/**
 * The actual PEP-as-gateway (BUILD_PLAN.md AP-2's "all traffic to protected
 * applications routes through the platform's PEP" vision) -- until now,
 * continuous enforcement was only ever proven via direct calls to
 * POST /api/v1/enforce, never against real forwarded application traffic.
 * This is a deliberately minimal, hand-rolled reverse proxy (not Spring
 * Cloud Gateway, which is WebFlux-based and would be a bigger paradigm
 * shift than this MVP piece warrants) -- config-driven: point
 * iam.enforcement.proxy.upstream-url at any app and every request under
 * the "/proxy" path prefix is enforced (the exact same session+location+
 * policy check POST /api/v1/enforce already does) before being forwarded.
 * A denied request never reaches the upstream at all.
 *
 * Two ways a caller can prove who they are, tried in this order:
 * 1. X-Session-Token header -- the original, unchanged path, for direct
 *    API-style callers that already hold a raw platform session token.
 * 2. A gateway-issued cookie -- for a plain browser with neither header nor
 *    cookie, the gateway acts as its own OpenID Connect Relying Party (see
 *    GatewayOidcClient) and drives the browser through the platform's
 *    existing login flow, coming back with a cookie the gateway itself
 *    understands. This is the piece that lets a real third-party app (a
 *    real deployed Pulse, for example) sit behind this gateway using its
 *    normal cookie-based browser session, instead of requiring it to speak
 *    this platform's internal X-Session-Token convention directly. See
 *    docs/DECISIONS.md, gateway cookie-login entry.
 */
@RestController
class ProxyController(
    private val enforcementService: EnforcementService,
    private val gatewayOidcClient: GatewayOidcClient,
    @Value("\${iam.enforcement.proxy.upstream-url:}") private val upstreamUrl: String,
    @Value("\${iam.enforcement.proxy.gateway.cookie-name:iam_gw_session}") private val cookieName: String,
    @Value("\${iam.enforcement.proxy.gateway.cookie-secure:true}") private val cookieSecure: Boolean,
    restClientBuilder: RestClient.Builder,
) {
    // Reuses iam-service-kit's bounded-timeout builder for the same
    // never-an-unbounded-wait reasoning as every other outbound call in
    // this platform (Guardrails Section 2) -- the mTLS wiring it also
    // provides is a harmless no-op here since the upstream is plain HTTP.
    private val client = resilientRestClientBuilder(restClientBuilder, "").build()

    @RequestMapping("/proxy/**")
    fun proxy(request: HttpServletRequest, response: HttpServletResponse) {
        if (upstreamUrl.isBlank()) {
            response.status = 503
            response.writer.write("Gateway upstream not configured (iam.enforcement.proxy.upstream-url)")
            return
        }

        val sourceIp = request.remoteAddr
        val headerToken = request.getHeader("X-Session-Token")
        val cookieToken = request.cookies?.firstOrNull { it.name == cookieName }?.value

        val identity: GatewayIdentity = when {
            !headerToken.isNullOrBlank() -> {
                try {
                    val result = enforcementService.enforce(headerToken, EnforceRequest(sourceIp))
                    GatewayIdentity(userId = result.userId, tenantId = result.tenantId)
                } catch (ex: EnforcementDeniedException) {
                    response.status = 401
                    response.writer.write(ex.message ?: "denied")
                    return
                }
            }
            !cookieToken.isNullOrBlank() -> {
                val userInfo = gatewayOidcClient.userInfo(cookieToken)
                if (userInfo == null) {
                    clearSessionCookie(response)
                    redirectToLogin(request, response)
                    return
                }
                val check = enforcementService.checkLocationAndPolicy(
                    UUID.fromString(userInfo.tenant_id), UUID.fromString(userInfo.sub), sourceIp,
                )
                if (!check.allowed) {
                    if (check.shouldTerminate) {
                        runCatching { gatewayOidcClient.terminate(cookieToken, check.reason ?: "denied by policy") }
                    }
                    clearSessionCookie(response)
                    response.status = 401
                    response.writer.write(check.reason ?: "denied")
                    return
                }
                GatewayIdentity(userId = UUID.fromString(userInfo.sub), tenantId = UUID.fromString(userInfo.tenant_id), email = userInfo.email)
            }
            else -> {
                if (!gatewayOidcClient.isConfigured) {
                    response.status = 401
                    response.writer.write("Missing X-Session-Token")
                    return
                }
                redirectToLogin(request, response)
                return
            }
        }

        forwardToUpstream(request, response, stripCookie = cookieToken != null, identity = identity)
    }

    /** No X-Session-Token and no cookie yet -- send the browser through the platform's own login flow. */
    private fun redirectToLogin(request: HttpServletRequest, response: HttpServletResponse) {
        val nextPath = request.requestURI + (request.queryString?.let { "?$it" } ?: "")
        val state = Base64.getUrlEncoder().withoutPadding().encodeToString(nextPath.toByteArray(StandardCharsets.UTF_8))
        val authorizeUrl = try {
            gatewayOidcClient.buildAuthorizeUrl(state)
        } catch (ex: GatewayNotConfiguredException) {
            response.status = 503
            response.writer.write("Gateway login not configured (iam.enforcement.proxy.gateway.*)")
            return
        }
        response.status = 302
        response.setHeader("Location", authorizeUrl)
    }

    /** Where the browser lands after a successful login, carrying the OpenID Connect authorization code. */
    @GetMapping("/oauth2/callback")
    fun callback(
        @RequestParam code: String,
        @RequestParam(required = false) state: String?,
        response: HttpServletResponse,
    ) {
        val bundle = try {
            gatewayOidcClient.exchangeCode(code)
        } catch (ex: Exception) {
            response.status = 502
            response.writer.write("Login exchange failed: ${ex.message}")
            return
        }
        setSessionCookie(response, bundle.access_token, bundle.expires_in)
        response.status = 302
        response.setHeader("Location", decodeNextPath(state))
    }

    /** The third-party app has no idea this cookie exists, so it needs its own explicit logout entry point. */
    @GetMapping("/oauth2/logout")
    fun logout(request: HttpServletRequest, response: HttpServletResponse) {
        val token = request.cookies?.firstOrNull { it.name == cookieName }?.value
        if (token != null) {
            runCatching { gatewayOidcClient.terminate(token, "user logout") }
        }
        clearSessionCookie(response)
        response.status = 302
        response.setHeader("Location", "/proxy/")
    }

    // Open-redirect guard: only ever send the browser back into our own
    // /proxy path, never an absolute URL or a foreign host, even though the
    // state value round-trips through the browser and the OpenID Connect
    // Provider Service unchanged.
    private fun decodeNextPath(state: String?): String {
        val decoded = state?.let {
            runCatching { String(Base64.getUrlDecoder().decode(it), StandardCharsets.UTF_8) }.getOrNull()
        }
        return decoded?.takeIf { it.startsWith("/proxy") } ?: "/proxy/"
    }

    // jakarta.servlet.http.Cookie has no SameSite attribute -- built by hand
    // instead so SameSite is actually present on the wire.
    private fun setSessionCookie(response: HttpServletResponse, value: String, maxAgeSeconds: Long) {
        response.addHeader("Set-Cookie", cookieHeader(value, maxAgeSeconds))
    }

    private fun clearSessionCookie(response: HttpServletResponse) {
        response.addHeader("Set-Cookie", cookieHeader("", 0))
    }

    private fun cookieHeader(value: String, maxAgeSeconds: Long): String {
        val secureAttr = if (cookieSecure) "; Secure" else ""
        return "$cookieName=$value; Path=/; HttpOnly; SameSite=Lax; Max-Age=$maxAgeSeconds$secureAttr"
    }

    private fun forwardToUpstream(request: HttpServletRequest, response: HttpServletResponse, stripCookie: Boolean, identity: GatewayIdentity) {
        val path = request.requestURI.removePrefix(request.contextPath).removePrefix("/proxy")
        val query = request.queryString?.let { "?$it" } ?: ""
        val targetUrl = "$upstreamUrl$path$query"
        val method = HttpMethod.valueOf(request.method)
        val bodyBytes = request.inputStream.readBytes()

        try {
            val upstreamResponse = client.method(method)
                .uri(targetUrl)
                .headers { headers ->
                    val names = request.headerNames
                    while (names.hasMoreElements()) {
                        val name = names.nextElement()
                        // Never forward the session token upstream (the
                        // protected app has no business seeing it), a stale
                        // Host header (would confuse the upstream's own
                        // routing), the Cookie header at all for a
                        // cookie-authenticated caller (carries our own
                        // gateway session cookie, and this MVP doesn't yet
                        // split out an upstream app's own cookies from ours
                        // -- flagged, not hidden: docs/DECISIONS.md), or any
                        // caller-supplied X-Auth-* header -- those are only
                        // ever trustworthy when the gateway itself sets
                        // them below, right after this loop; forwarding a
                        // caller-supplied one first would let a caller
                        // impersonate any user simply by setting the header
                        // itself, if it somehow ever won the later add() (it
                        // wouldn't here, but never rely on that).
                        val skip = name.equals("host", ignoreCase = true) ||
                            name.equals("x-session-token", ignoreCase = true) ||
                            name.startsWith("x-auth-", ignoreCase = true) ||
                            (stripCookie && name.equals("cookie", ignoreCase = true))
                        if (!skip) {
                            headers.add(name, request.getHeader(name))
                        }
                    }
                    // Trusted identity, asserted by the gateway after a
                    // passing enforcement check -- the upstream app can rely
                    // on these without doing any login work itself.
                    headers.add("X-Auth-User-Id", identity.userId.toString())
                    headers.add("X-Auth-Tenant-Id", identity.tenantId.toString())
                    identity.email?.let { headers.add("X-Auth-User-Email", it) }
                }
                .body(bodyBytes)
                .retrieve()
                .toEntity(ByteArray::class.java)

            response.status = upstreamResponse.statusCode.value()
            // HttpHeaders resolves .forEach to Java's Map.forEach(BiConsumer),
            // not Kotlin's Iterable<Map.Entry<K,V>>.forEach -- a two-param
            // lambda, not a destructured single param.
            upstreamResponse.headers.forEach { name, values -> values.forEach { v -> response.addHeader(name, v) } }
            upstreamResponse.body?.let { response.outputStream.write(it) }
        } catch (ex: RestClientResponseException) {
            response.status = ex.statusCode.value()
            response.outputStream.write(ex.responseBodyAsByteArray)
        } catch (ex: Exception) {
            response.status = 502
            response.writer.write("Upstream unreachable: ${ex.message}")
        }
    }
}
