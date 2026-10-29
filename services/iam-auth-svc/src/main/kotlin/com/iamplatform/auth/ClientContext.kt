package com.iamplatform.auth

import jakarta.servlet.http.HttpServletRequest

/**
 * Who is really signing in and from what, worked out on the server instead of taken from the request
 * body (which a caller could set to anything, defeating the country/IP policy and the audit trail).
 *
 * The public reverse proxy (Caddy) sets X-Forwarded-For to the address it actually saw, replacing any
 * value the client sent, so the LAST hop is the real client. Trusted internal callers (the login
 * portal) reach this service directly with no such header and supply the IP they derived themselves.
 * This is only safe while the proxy is the only public way in: the raw service ports must not be
 * reachable from the internet (see docs/DECISIONS.md, 2026-10-29 entry).
 */
object ClientContext {
    private const val MAX_UA = 512

    fun ip(forwardedFor: String?, bodyIp: String?, remoteAddr: String?): String {
        val proxied = forwardedFor?.split(",")?.map { it.trim() }?.lastOrNull { it.isNotEmpty() }
        val chosen = proxied ?: bodyIp?.trim()?.takeIf { it.isNotEmpty() } ?: remoteAddr.orEmpty()
        return chosen.removePrefix("::ffff:")
    }

    fun userAgent(bodyUserAgent: String?, headerUserAgent: String?): String? =
        (bodyUserAgent?.takeIf { it.isNotBlank() } ?: headerUserAgent?.takeIf { it.isNotBlank() })?.take(MAX_UA)

    fun resolve(servletRequest: HttpServletRequest, bodyIp: String?, bodyUserAgent: String?): Pair<String, String?> =
        ip(servletRequest.getHeader("X-Forwarded-For"), bodyIp, servletRequest.remoteAddr) to
            userAgent(bodyUserAgent, servletRequest.getHeader("User-Agent"))
}
