package com.iamplatform.auth

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter

/**
 * Keeps service-to-service endpoints off the public internet.
 *
 * The public reverse proxy (Caddy) forwards every request for the auth address to this service and always adds
 * `X-Forwarded-*` headers; a call from another platform service (the login portal) goes straight to the container and
 * carries none. A request on a guarded path that arrives WITH a forwarding header came from outside and is answered 404, as
 * if the route did not exist. Same mechanism as iam-tenant-svc's filter of the same name.
 *
 * Guarded here: the device-enrollment sign-in, which is exempt from the tenant's "authorised laptop to sign in" rule
 * (see AuthService.login). If this route were reachable from the internet the rule could be skipped by anyone.
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
        private val GUARDED_PREFIXES = listOf("/internal/")
        private val PROXY_HEADERS = listOf("X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "Forwarded", "X-Real-IP")

        fun isGuarded(uri: String): Boolean = GUARDED_PREFIXES.any { uri.startsWith(it) }

        fun arrivedThroughProxy(request: HttpServletRequest): Boolean = PROXY_HEADERS.any { request.getHeader(it) != null }
    }
}
