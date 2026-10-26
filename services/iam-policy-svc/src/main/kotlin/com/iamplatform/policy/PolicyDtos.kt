package com.iamplatform.policy

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import java.time.Instant
import java.util.UUID

data class PutPolicyRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotNull
    val scope: PolicyScope,

    val scopeId: UUID? = null,

    val allowedCountries: List<String>? = null,
    val allowedCountriesHardCap: Boolean = false,
    val blockedCountries: List<String>? = null,
    val blockedCountriesHardCap: Boolean = false,

    val allowedCidrs: List<String>? = null,
    val allowedCidrsHardCap: Boolean = false,
    val blockedCidrs: List<String>? = null,
    val blockedCidrsHardCap: Boolean = false,

    val mfaRequired: Boolean? = null,
    val mfaRequiredHardCap: Boolean = false,

    val totpReenrollEveryLogin: Boolean? = null,
    val totpReenrollEveryLoginHardCap: Boolean = false,
)

data class PolicyResponse(
    val id: UUID,
    val tenantId: UUID,
    val scope: PolicyScope,
    val scopeId: UUID,
    val allowedCountries: List<String>?,
    val allowedCountriesHardCap: Boolean,
    val blockedCountries: List<String>?,
    val blockedCountriesHardCap: Boolean,
    val allowedCidrs: List<String>?,
    val allowedCidrsHardCap: Boolean,
    val blockedCidrs: List<String>?,
    val blockedCidrsHardCap: Boolean,
    val mfaRequired: Boolean?,
    val mfaRequiredHardCap: Boolean,
    val totpReenrollEveryLogin: Boolean?,
    val totpReenrollEveryLoginHardCap: Boolean,
    val updatedAt: Instant,
)

fun PolicyEntity.toResponse(): PolicyResponse =
    PolicyResponse(
        id = id,
        tenantId = tenantId,
        scope = scope,
        scopeId = scopeId,
        allowedCountries = allowedCountriesList,
        allowedCountriesHardCap = allowedCountriesHardCap,
        blockedCountries = blockedCountriesList,
        blockedCountriesHardCap = blockedCountriesHardCap,
        allowedCidrs = allowedCidrsList,
        allowedCidrsHardCap = allowedCidrsHardCap,
        blockedCidrs = blockedCidrsList,
        blockedCidrsHardCap = blockedCidrsHardCap,
        mfaRequired = mfaRequired,
        mfaRequiredHardCap = mfaRequiredHardCap,
        totpReenrollEveryLogin = totpReenrollEveryLogin,
        totpReenrollEveryLoginHardCap = totpReenrollEveryLoginHardCap,
        updatedAt = updatedAt,
    )

data class EvaluateRequest(
    @field:NotNull
    val tenantId: UUID,

    val ouId: UUID? = null,
    val userId: UUID? = null,

    @field:NotBlank
    val country: String,

    // Added for per-user/group IP allowlisting. Optional -- callers that
    // don't pass it simply can't be matched against an allowedCidrs list
    // (which then fails closed, see PolicyEvaluator).
    val sourceIp: String? = null,
)

data class EvaluateResponse(
    val allowed: Boolean,
    val reason: String?,
    val policyScopeApplied: PolicyScope?,
    val mfaRequired: Boolean,
    val totpReenrollEveryLogin: Boolean,
)

class InvalidPolicyRequestException(message: String) : RuntimeException(message)

// Added for Service 14 (iam-admin-console).
class PolicyNotFoundException(tenantId: UUID, scope: PolicyScope, scopeId: UUID) :
    RuntimeException("No policy stored for tenant $tenantId at scope=$scope scopeId=$scopeId")
