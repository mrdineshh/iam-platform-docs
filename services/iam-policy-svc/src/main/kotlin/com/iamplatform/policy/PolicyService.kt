package com.iamplatform.policy

import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import java.util.UUID

@Service
class PolicyService(
    private val repository: PolicyRepository,
    private val auditPublisher: AuditPublisher,
) {

    fun putPolicy(request: PutPolicyRequest): PolicyEntity {
        val effectiveScopeId = when (request.scope) {
            PolicyScope.TENANT -> request.tenantId
            PolicyScope.OU, PolicyScope.USER ->
                request.scopeId ?: throw InvalidPolicyRequestException("scopeId is required for scope=${request.scope}")
        }

        if (request.scope != PolicyScope.TENANT &&
            (request.allowedCountriesHardCap || request.blockedCountriesHardCap ||
                request.allowedCidrsHardCap || request.blockedCidrsHardCap || request.mfaRequiredHardCap ||
                request.totpReenrollEveryLoginHardCap)
        ) {
            throw InvalidPolicyRequestException("hard-cap flags may only be set on scope=TENANT")
        }

        validateSecuritySettings(request)

        val existing = repository.findByTenantIdAndScopeAndScopeId(request.tenantId, request.scope, effectiveScopeId)
        val policy = existing ?: PolicyEntity(
            id = UUID.randomUUID(),
            tenantId = request.tenantId,
            scope = request.scope,
            scopeId = effectiveScopeId,
        )

        policy.allowedCountries = request.allowedCountries.toCsv()
        policy.allowedCountriesHardCap = request.allowedCountriesHardCap
        policy.blockedCountries = request.blockedCountries.toCsv()
        policy.blockedCountriesHardCap = request.blockedCountriesHardCap
        policy.allowedCidrs = request.allowedCidrs.toCsv()
        policy.allowedCidrsHardCap = request.allowedCidrsHardCap
        policy.blockedCidrs = request.blockedCidrs.toCsv()
        policy.blockedCidrsHardCap = request.blockedCidrsHardCap
        policy.mfaRequired = request.mfaRequired
        policy.mfaRequiredHardCap = request.mfaRequiredHardCap
        policy.totpReenrollEveryLogin = request.totpReenrollEveryLogin
        policy.totpReenrollEveryLoginHardCap = request.totpReenrollEveryLoginHardCap
        policy.passwordMinLength = request.passwordMinLength
        policy.passwordRequireUppercase = request.passwordRequireUppercase
        policy.passwordRequireLowercase = request.passwordRequireLowercase
        policy.passwordRequireDigit = request.passwordRequireDigit
        policy.passwordRequireSymbol = request.passwordRequireSymbol
        policy.lockoutThreshold = request.lockoutThreshold
        policy.lockoutDurationMinutes = request.lockoutDurationMinutes
        policy.lockoutPermanent = request.lockoutPermanent
        policy.updatedAt = java.time.Instant.now()

        val saved = repository.save(policy)

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = saved.tenantId,
                actorType = ActorType.SYSTEM,
                actorId = "iam-policy-svc",
                action = "policy.updated",
                result = AuditResult.SUCCESS,
                policyScopeApplied = saved.scope.name,
            ),
        )

        return saved
    }

    // Password rules and lockout are per tenant (FR-3.1, FR-3.5), so they are
    // only accepted on the TENANT policy, and range-checked so a typo can't
    // lock every user out (e.g. a 0-minute lockout) or accept absurd values.
    private fun validateSecuritySettings(request: PutPolicyRequest) {
        val hasAny = listOf(
            request.passwordMinLength, request.passwordRequireUppercase, request.passwordRequireLowercase,
            request.passwordRequireDigit, request.passwordRequireSymbol, request.lockoutThreshold,
            request.lockoutDurationMinutes, request.lockoutPermanent,
        ).any { it != null }
        if (!hasAny) return

        if (request.scope != PolicyScope.TENANT) {
            throw InvalidPolicyRequestException("password and lockout settings may only be set on scope=TENANT")
        }
        request.passwordMinLength?.let {
            if (it !in 8..128) throw InvalidPolicyRequestException("passwordMinLength must be between 8 and 128")
        }
        request.lockoutThreshold?.let {
            if (it !in 0..100) throw InvalidPolicyRequestException("lockoutThreshold must be between 0 (off) and 100")
        }
        request.lockoutDurationMinutes?.let {
            if (it !in 1..10080) throw InvalidPolicyRequestException("lockoutDurationMinutes must be between 1 and 10080")
        }
    }

    /** Effective settings for a tenant: stored TENANT values, platform defaults for anything unset. */
    fun securitySettings(tenantId: UUID): SecuritySettingsResponse {
        val tenant = repository.findByTenantIdAndScopeAndScopeId(tenantId, PolicyScope.TENANT, tenantId)
        return SecuritySettingsResponse(
            passwordMinLength = tenant?.passwordMinLength ?: SecuritySettingsResponse.DEFAULT_MIN_LENGTH,
            passwordRequireUppercase = tenant?.passwordRequireUppercase ?: false,
            passwordRequireLowercase = tenant?.passwordRequireLowercase ?: false,
            passwordRequireDigit = tenant?.passwordRequireDigit ?: false,
            passwordRequireSymbol = tenant?.passwordRequireSymbol ?: false,
            lockoutThreshold = tenant?.lockoutThreshold ?: 0,
            lockoutDurationMinutes = tenant?.lockoutDurationMinutes ?: SecuritySettingsResponse.DEFAULT_LOCKOUT_MINUTES,
            lockoutPermanent = tenant?.lockoutPermanent ?: false,
        )
    }

    // Added for Service 14 (iam-admin-console) -- fetches the raw stored
    // policy at an exact scope (not the merged/evaluated result), so the
    // console can pre-fill an edit form with what's actually stored.
    fun getPolicy(tenantId: UUID, scope: PolicyScope, scopeId: UUID?): PolicyEntity {
        val effectiveScopeId = when (scope) {
            PolicyScope.TENANT -> tenantId
            PolicyScope.OU, PolicyScope.USER ->
                scopeId ?: throw InvalidPolicyRequestException("scopeId is required for scope=$scope")
        }
        return repository.findByTenantIdAndScopeAndScopeId(tenantId, scope, effectiveScopeId)
            ?: throw PolicyNotFoundException(tenantId, scope, effectiveScopeId)
    }

    fun evaluate(request: EvaluateRequest): PolicyEvaluationResult {
        val tenantPolicy = repository.findByTenantIdAndScopeAndScopeId(request.tenantId, PolicyScope.TENANT, request.tenantId)
        val ouPolicy = request.ouId?.let {
            repository.findByTenantIdAndScopeAndScopeId(request.tenantId, PolicyScope.OU, it)
        }
        val userPolicy = request.userId?.let {
            repository.findByTenantIdAndScopeAndScopeId(request.tenantId, PolicyScope.USER, it)
        }

        return PolicyEvaluator.evaluate(tenantPolicy, ouPolicy, userPolicy, request.country, request.sourceIp)
    }
}
