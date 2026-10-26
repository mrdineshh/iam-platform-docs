package com.iamplatform.servicekit.correlation

import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.slf4j.MDC
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.web.filter.OncePerRequestFilter

/**
 * Every inbound request either carries or is assigned an X-Correlation-Id.
 * It is echoed on the response, stashed in MDC for log lines, and made
 * available via CorrelationId.get() for outbound calls and audit events
 * originating from this request. BUILD_PLAN.md Section 4.4.
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
class CorrelationIdFilter : OncePerRequestFilter() {

    override fun doFilterInternal(
        request: HttpServletRequest,
        response: HttpServletResponse,
        filterChain: FilterChain,
    ) {
        val correlationId = request.getHeader(CorrelationId.HEADER)?.takeIf { it.isNotBlank() }
            ?: CorrelationId.generate()

        CorrelationId.set(correlationId)
        MDC.put(CorrelationId.MDC_KEY, correlationId)
        response.setHeader(CorrelationId.HEADER, correlationId)

        try {
            filterChain.doFilter(request, response)
        } finally {
            MDC.remove(CorrelationId.MDC_KEY)
            CorrelationId.clear()
        }
    }
}
