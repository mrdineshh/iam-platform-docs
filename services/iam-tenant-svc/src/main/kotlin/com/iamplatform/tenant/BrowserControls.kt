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
import jakarta.servlet.http.HttpServletRequest
import jakarta.validation.Valid
import jakarta.validation.constraints.NotNull
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant
import java.util.UUID

/**
 * Tenant-wide browser controls that an administrator switches from the Admin Console and the endpoint agent applies
 * (docs/DECISIONS.md, 2026-11-19: "central switch for the personal Microsoft sign-in block"). Off by default: a tenant with
 * no row behaves as if every switch were off.
 *
 * The setting travels to the laptops in the device policy, in its OWN signed block (see
 * [DevicePolicyCanonical.encodeBrowserControls]) so that the policy signature every installed agent already checks does not
 * change by a single byte. An agent that does not know about browser controls simply ignores the block.
 */
@Entity
@Table(name = "tenant_browser_controls")
class TenantBrowserControlsEntity(
    @Id @Column(name = "tenant_id") var tenantId: UUID,
    @Column(name = "block_personal_microsoft", nullable = false) var blockPersonalMicrosoft: Boolean = false,
    @Column(name = "updated_at", nullable = false) var updatedAt: Instant = Instant.now(),
    @Column(name = "updated_by", length = 64) var updatedBy: String? = null,
)

interface TenantBrowserControlsRepository : JpaRepository<TenantBrowserControlsEntity, UUID>

data class BrowserControlsResponse(val blockPersonalMicrosoft: Boolean)

data class BrowserControlsRequest(@field:NotNull val blockPersonalMicrosoft: Boolean?)

@Service
class BrowserControlsService(
    private val controls: TenantBrowserControlsRepository,
    private val auditPublisher: AuditPublisher,
) {
    fun isBlockingPersonalMicrosoft(tenantId: UUID): Boolean =
        controls.findById(tenantId).map { it.blockPersonalMicrosoft }.orElse(false)

    @Transactional
    fun setBlockPersonalMicrosoft(tenantId: UUID, blocked: Boolean, actorId: String, sourceIp: String?) {
        val existing = controls.findById(tenantId).orElse(null)
        // Switching to what it already is changes nothing and is not recorded as a decision.
        if (existing != null && existing.blockPersonalMicrosoft == blocked) return
        if (existing == null && !blocked) return
        val row = existing ?: TenantBrowserControlsEntity(tenantId)
        row.blockPersonalMicrosoft = blocked
        row.updatedAt = Instant.now()
        row.updatedBy = actorId
        controls.save(row)
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.ADMIN,
                actorId = actorId,
                action = if (blocked) "tenant.browser_controls.personal_microsoft_block.enabled" else "tenant.browser_controls.personal_microsoft_block.disabled",
                result = AuditResult.SUCCESS,
                sourceIp = sourceIp,
            ),
        )
    }
}

@RestController
@RequestMapping("/api/v1/endpoint/browser-controls")
class BrowserControlsController(
    private val service: BrowserControlsService,
    private val adminAccessGuard: AdminAccessGuard,
) {
    @GetMapping
    fun get(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<BrowserControlsResponse> {
        adminAccessGuard.requireValidSession(sessionToken)
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(BrowserControlsResponse(service.isBlockingPersonalMicrosoft(tenantId)))
    }

    @PutMapping
    fun put(
        @RequestParam tenantId: UUID,
        @Valid @RequestBody request: BrowserControlsRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<BrowserControlsResponse> {
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        service.setBlockPersonalMicrosoft(tenantId, request.blockPersonalMicrosoft!!, admin.userId.toString(), httpRequest.remoteAddr)
        return ResponseEntity.ok(BrowserControlsResponse(request.blockPersonalMicrosoft))
    }
}
