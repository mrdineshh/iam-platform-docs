package com.iamplatform.tenant

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

/**
 * Keeps service-to-service endpoints off the public internet.
 *
 * The public reverse proxy (Caddy) forwards every request for the tenant address to this service and always adds
 * `X-Forwarded-*` headers; a call from another platform service goes straight to the container and carries none. So a
 * request on a path guarded here that arrives WITH a forwarding header came from outside and is answered 404, as if the
 * route did not exist.
 *
 * Scope is deliberately limited to the device-bound sign-in challenge routes and the operator's agent-release upload. The older `/internal/devices/...` route
 * (OQ-24) is not changed by this filter, so nothing that already works is affected.
 */
@Component
class InternalOnlyFilter : OncePerRequestFilter() {

    override fun shouldNotFilter(request: HttpServletRequest): Boolean = !isGuarded(request.requestURI)

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, chain: FilterChain) {
        if (arrivedThroughProxy(request)) {
            response.status = HttpServletResponse.SC_NOT_FOUND
            return
        }
        chain.doFilter(request, response)
    }

    companion object {
        private val GUARDED_PREFIXES = listOf("/internal/device-challenges", "/internal/agent-releases", "/internal/login-device-check")
        private val PROXY_HEADERS = listOf("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-IP")

        fun isGuarded(uri: String): Boolean = GUARDED_PREFIXES.any { uri == it || uri.startsWith("$it/") }

        fun arrivedThroughProxy(request: HttpServletRequest): Boolean = PROXY_HEADERS.any { request.getHeader(it) != null }
    }
}
