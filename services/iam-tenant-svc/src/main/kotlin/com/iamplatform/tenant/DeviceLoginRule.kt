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
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.time.Instant
import java.util.UUID

/**
 * Platform-level sign-in rule (docs/DECISIONS.md, 2026-11-19): when on for a tenant, a non-administrator can only sign in
 * from an approved, compliant laptop, and is told so at the sign-in screen instead of being let in and refused app by app.
 * Off by default: a tenant with no row behaves exactly as before.
 */
@Entity
@Table(name = "tenant_device_login_rule")
class TenantDeviceLoginRuleEntity(
    @Id @Column(name = "tenant_id") var tenantId: UUID,
    @Column(name = "require_trusted_device", nullable = false) var requireTrustedDevice: Boolean = false,
    @Column(name = "updated_at", nullable = false) var updatedAt: Instant = Instant.now(),
    @Column(name = "updated_by", length = 64) var updatedBy: String? = null,
)

interface TenantDeviceLoginRuleRepository : JpaRepository<TenantDeviceLoginRuleEntity, UUID>

data class DeviceLoginRuleResponse(val requireTrustedDevice: Boolean)

data class DeviceLoginRuleRequest(@field:NotNull val requireTrustedDevice: Boolean?)

/** Asked by iam-auth-svc after the password and second factor succeeded and before any session is issued. */
data class LoginDeviceCheckRequest(
    @field:NotNull val tenantId: UUID?,
    @field:NotNull val userId: UUID?,
    @field:NotBlank val role: String,
    // The device whose signed proof was just verified, if any. Null when the sign-in carried no valid proof.
    val deviceId: String? = null,
)

/** [code] is one of DEVICE_REQUIRED, DEVICE_NOT_APPROVED, DEVICE_NON_COMPLIANT when [allowed] is false. */
data class LoginDeviceCheckResponse(val allowed: Boolean, val code: String? = null, val detail: String? = null)

@Service
class DeviceLoginRuleService(
    private val rules: TenantDeviceLoginRuleRepository,
    private val gate: TrustedDeviceGate,
    private val auditPublisher: AuditPublisher,
) {
    fun isRequired(tenantId: UUID): Boolean = rules.findById(tenantId).map { it.requireTrustedDevice }.orElse(false)

    @Transactional
    fun set(tenantId: UUID, required: Boolean, actorId: String, sourceIp: String?) {
        val row = rules.findById(tenantId).orElse(null) ?: TenantDeviceLoginRuleEntity(tenantId)
        if (row.requireTrustedDevice == required && rules.existsById(tenantId)) return
        row.requireTrustedDevice = required
        row.updatedAt = Instant.now()
        row.updatedBy = actorId
        rules.save(row)
        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = tenantId,
                actorType = ActorType.ADMIN,
                actorId = actorId,
                action = if (required) "tenant.device_login_rule.enabled" else "tenant.device_login_rule.disabled",
                result = AuditResult.SUCCESS,
                sourceIp = sourceIp,
            ),
        )
    }

    /**
     * Whether this sign-in may become a session. Administrators are never held to the rule: a laptop or agent that stops
     * working must not lock every admin out of the console that fixes it. Denials are audited by iam-auth-svc (which owns the
     * sign-in); only the exception use is recorded here, because only this service knows an exception was what let it through.
     */
    fun check(request: LoginDeviceCheckRequest): LoginDeviceCheckResponse {
        val tenantId = request.tenantId!!
        val userId = request.userId!!
        if (request.role.equals("ADMIN", ignoreCase = true)) return ALLOWED
        if (!isRequired(tenantId)) return ALLOWED

        val verdict = gate.evaluateDevice(tenantId, userId, request.deviceId, allowPending = false)
        return when (verdict.denial) {
            null -> {
                if (verdict.exceptionUsed) {
                    auditPublisher.publish(
                        AuditEvent(
                            correlationId = CorrelationId.get(),
                            tenantId = tenantId,
                            actorType = ActorType.USER,
                            actorId = userId.toString(),
                            action = "auth.login.allowed_compliance_exception",
                            result = AuditResult.SUCCESS,
                            reason = "exception until ${verdict.exceptionUntil}",
                            deviceId = verdict.deviceId.toString(),
                        ),
                    )
                }
                ALLOWED
            }
            DeviceDenial.NO_DEVICE, DeviceDenial.NOT_REGISTERED -> LoginDeviceCheckResponse(false, "DEVICE_REQUIRED")
            DeviceDenial.NOT_APPROVED ->
                LoginDeviceCheckResponse(false, "DEVICE_NOT_APPROVED", verdict.status.orEmpty().lowercase().replace('_', ' '))
            DeviceDenial.NON_COMPLIANT -> LoginDeviceCheckResponse(false, "DEVICE_NON_COMPLIANT")
        }
    }

    private companion object {
        val ALLOWED = LoginDeviceCheckResponse(true)
    }
}

@RestController
@RequestMapping("/api/v1/endpoint/login-rule")
class DeviceLoginRuleController(
    private val service: DeviceLoginRuleService,
    private val adminAccessGuard: AdminAccessGuard,
) {
    @GetMapping
    fun get(
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Session-Token") sessionToken: String,
    ): ResponseEntity<DeviceLoginRuleResponse> {
        adminAccessGuard.requireValidSession(sessionToken)
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        return ResponseEntity.ok(DeviceLoginRuleResponse(service.isRequired(tenantId)))
    }

    @PutMapping
    fun put(
        @RequestParam tenantId: UUID,
        @Valid @RequestBody request: DeviceLoginRuleRequest,
        @RequestHeader("X-Session-Token") sessionToken: String,
        httpRequest: HttpServletRequest,
    ): ResponseEntity<DeviceLoginRuleResponse> {
        val admin = adminAccessGuard.requireValidSession(sessionToken)
        adminAccessGuard.requireTenantAdmin(sessionToken, tenantId)
        service.set(tenantId, request.requireTrustedDevice!!, admin.userId.toString(), httpRequest.remoteAddr)
        return ResponseEntity.ok(DeviceLoginRuleResponse(request.requireTrustedDevice))
    }
}

/** Service-to-service only: InternalOnlyFilter answers 404 to anything that arrived through the public proxy. */
@RestController
@RequestMapping("/internal/login-device-check")
class LoginDeviceCheckController(private val service: DeviceLoginRuleService) {
    @PostMapping
    fun check(@Valid @RequestBody request: LoginDeviceCheckRequest): ResponseEntity<LoginDeviceCheckResponse> =
        ResponseEntity.ok(service.check(request))
}
