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
