package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import jakarta.validation.Valid
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.net.URI
import java.time.Instant
import java.util.UUID

@Entity
@Table(name = "tenant_branding")
class TenantBrandingEntity(
    @Id
    @Column(name = "tenant_id")
    var tenantId: UUID,

    @Column(name = "primary_color", length = 7)
    var primaryColor: String? = null,

    @Column(name = "logo_url", length = 1024)
    var logoUrl: String? = null,

    @Column(name = "headline", length = 120)
    var headline: String? = null,

    @Column(name = "default_theme", length = 8)
    var defaultTheme: String? = null,

    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),
)

interface TenantBrandingRepository : JpaRepository<TenantBrandingEntity, UUID>

/** Public by design: rendered on the pre-login page, so never put a secret in here. */
data class BrandingResponse(
    val primaryColor: String?,
    val logoUrl: String?,
    val headline: String?,
    val defaultTheme: String?,
)

fun TenantBrandingEntity.toResponse() = BrandingResponse(primaryColor, logoUrl, headline, defaultTheme)

data class UpdateBrandingRequest(
    @field:NotNull
    val tenantId: UUID,

    // #RRGGBB only: the value is injected into CSS custom properties on the
    // login page, so anything looser is a CSS-injection vector.
    @field:Pattern(regexp = "^#[0-9a-fA-F]{6}$", message = "must be a #RRGGBB color")
    val primaryColor: String? = null,

    // https only, so the logo can never be a javascript: or data: URL.
    @field:Size(max = 1024)
    @field:Pattern(regexp = "^https://[^\\s]+$", message = "must be an https:// URL")
    val logoUrl: String? = null,

    @field:Size(max = 120)
    val headline: String? = null,

    @field:Pattern(regexp = "^(light|dark)$", message = "must be light or dark")
    val defaultTheme: String? = null,
)

class InvalidBrandingException(message: String) : RuntimeException(message)

@Service
class TenantBrandingService(
    private val repository: TenantBrandingRepository,
    private val tenantRepository: TenantRepository,
    private val auditPublisher: AuditPublisher,
) {
    fun find(tenantId: UUID): TenantBrandingEntity? = repository.findById(tenantId).orElse(null)

    fun update(request: UpdateBrandingRequest, actorId: UUID, sourceIp: String?): TenantBrandingEntity {
        if (!tenantRepository.existsById(request.tenantId)) throw TenantNotFoundException(request.tenantId)

        val logoUrl = request.logoUrl?.trim()?.takeIf { it.isNotEmpty() }
        if (logoUrl != null) {
            val uri = runCatching { URI(logoUrl) }.getOrNull()
            if (uri == null || uri.scheme != "https" || uri.host.isNullOrBlank()) {
                throw InvalidBrandingException("logoUrl must be a valid https:// URL")
            }
        }

        val saved = repository.save(
            (repository.findById(request.tenantId).orElse(null) ?: TenantBrandingEntity(request.tenantId)).apply {
                primaryColor = request.primaryColor?.lowercase()
                this.logoUrl = logoUrl
                headline = request.headline?.trim()?.takeIf { it.isNotEmpty() }
                defaultTheme = request.defaultTheme
                updatedAt = Instant.now()
            },
        )

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = request.tenantId,
                actorType = ActorType.ADMIN,
                actorId = actorId.toString(),
                action = "tenant.branding_updated",
                result = AuditResult.SUCCESS,
                reason = "color=${saved.primaryColor ?: "default"}; logo=${if (saved.logoUrl != null) "set" else "none"}; theme=${saved.defaultTheme ?: "default"}",
                sourceIp = sourceIp,
            ),
        )
        return saved
    }
}

@RestController
@RequestMapping("/api/v1/admin/branding")
class TenantBrandingController(
    private val brandingService: TenantBrandingService,
    private val adminAccessGuard: AdminAccessGuard,
) {
    // Sending every field as null resets the tenant to the platform default.
    @PutMapping
    fun update(
        @Valid @RequestBody request: UpdateBrandingRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: jakarta.servlet.http.HttpServletRequest,
    ): ResponseEntity<BrandingResponse> {
        adminAccessGuard.requireTenantAdmin(sessionToken, request.tenantId)
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        return ResponseEntity.ok(brandingService.update(request, admin.userId, httpRequest.remoteAddr).toResponse())
    }
}
