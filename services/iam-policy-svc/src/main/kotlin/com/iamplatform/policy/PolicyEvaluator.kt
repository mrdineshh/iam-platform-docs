package com.iamplatform.policy

data class PolicyEvaluationResult(
    val allowed: Boolean,
    val reason: String?,
    val policyScopeApplied: PolicyScope?,
    // Resolved separately from allowed/denied -- this is advisory for the
    // caller (iam-auth-svc decides whether to prompt for a 2FA code), not
    // itself a pass/fail gate. Defaults to true (never fail open on
    // whether MFA is needed) when no scope expresses an opinion.
    val mfaRequired: Boolean = true,
    // Same advisory nature as mfaRequired, opposite default: "false" (keep
    // the existing enrolled device) is the safe/normal behavior. When true,
    // every fresh login (no code submitted yet) resets the device and
    // issues a brand-new QR instead of asking for the existing code.
    val totpReenrollEveryLogin: Boolean = false,
)

/**
 * The merge-with-hard-cap resolver (AP-4 / BRD FR-4.2). Pure function, no
 * Spring/DB dependency, so this is testable exhaustively without wiring up
 * any infrastructure -- BUILD_PLAN.md Section 6 calls this out explicitly
 * ("heaviest unit-test surface... exhaustive coverage before any caller is
 * wired to it").
 *
 * Merge rule per attribute (allowedCountries, blockedCountries, allowedCidrs,
 * blockedCidrs, mfaRequired -- each independently):
 *  1. If the TENANT record marks this attribute as a hard-cap, its value
 *     wins unconditionally -- OU/USER values for that attribute are ignored.
 *  2. Otherwise, the most specific level that defines the attribute wins:
 *     USER > OU > TENANT. A level that leaves the attribute unset does not
 *     override -- it inherits from the next broader level (a merge, not a
 *     full override, per FR-4.2).
 *
 * Evaluation order: blockedCountries/blockedCidrs are checked first (an
 * explicit block always wins over an allow-list), then
 * allowedCountries/allowedCidrs (if defined, only listed values pass -- a
 * positive allow-list, not merely "not blocked"). mfaRequired is resolved
 * independently of the allow/deny outcome -- it's never itself a reason to
 * deny the request, just a flag the caller acts on.
 */
object PolicyEvaluator {

    fun evaluate(
        tenant: PolicyEntity?,
        ou: PolicyEntity?,
        user: PolicyEntity?,
        country: String,
        sourceIp: String? = null,
    ): PolicyEvaluationResult {
        val mfaRequired = resolveAttribute(
            tenantHardCap = tenant?.mfaRequiredHardCap ?: false,
            tenantValue = tenant?.mfaRequired,
            ouValue = ou?.mfaRequired,
            userValue = user?.mfaRequired,
        ).value ?: true

        val totpReenrollEveryLogin = resolveAttribute(
            tenantHardCap = tenant?.totpReenrollEveryLoginHardCap ?: false,
            tenantValue = tenant?.totpReenrollEveryLogin,
            ouValue = ou?.totpReenrollEveryLogin,
            userValue = user?.totpReenrollEveryLogin,
        ).value ?: false

        val blockedCountries = resolveAttribute(
            tenantHardCap = tenant?.blockedCountriesHardCap ?: false,
            tenantValue = tenant?.blockedCountriesList,
            ouValue = ou?.blockedCountriesList,
            userValue = user?.blockedCountriesList,
        )
        if (blockedCountries.value != null && country in blockedCountries.value) {
            return PolicyEvaluationResult(
                allowed = false,
                reason = "country '$country' is in blockedCountries",
                policyScopeApplied = blockedCountries.scope,
                mfaRequired = mfaRequired,
                totpReenrollEveryLogin = totpReenrollEveryLogin,
            )
        }

        val allowedCountries = resolveAttribute(
            tenantHardCap = tenant?.allowedCountriesHardCap ?: false,
            tenantValue = tenant?.allowedCountriesList,
            ouValue = ou?.allowedCountriesList,
            userValue = user?.allowedCountriesList,
        )
        if (allowedCountries.value != null && country !in allowedCountries.value) {
            return PolicyEvaluationResult(
                allowed = false,
                reason = "country '$country' is not in allowedCountries",
                policyScopeApplied = allowedCountries.scope,
                mfaRequired = mfaRequired,
                totpReenrollEveryLogin = totpReenrollEveryLogin,
            )
        }

        val blockedCidrs = resolveAttribute(
            tenantHardCap = tenant?.blockedCidrsHardCap ?: false,
            tenantValue = tenant?.blockedCidrsList,
            ouValue = ou?.blockedCidrsList,
            userValue = user?.blockedCidrsList,
        )
        if (sourceIp != null && blockedCidrs.value != null && CidrMatcher.anyMatches(sourceIp, blockedCidrs.value)) {
            return PolicyEvaluationResult(
                allowed = false,
                reason = "source IP '$sourceIp' is in blockedCidrs",
                policyScopeApplied = blockedCidrs.scope,
                mfaRequired = mfaRequired,
                totpReenrollEveryLogin = totpReenrollEveryLogin,
            )
        }

        val allowedCidrs = resolveAttribute(
            tenantHardCap = tenant?.allowedCidrsHardCap ?: false,
            tenantValue = tenant?.allowedCidrsList,
            ouValue = ou?.allowedCidrsList,
            userValue = user?.allowedCidrsList,
        )
        if (allowedCidrs.value != null) {
            // An allowedCidrs list exists for this user/OU/tenant -- a
            // missing or unmatched sourceIp both fail closed, same spirit
            // as "never fail open" (AP-2/4.6): no IP to check means deny,
            // not skip the check.
            if (sourceIp == null || !CidrMatcher.anyMatches(sourceIp, allowedCidrs.value)) {
                return PolicyEvaluationResult(
                    allowed = false,
                    reason = "source IP is not in allowedCidrs",
                    policyScopeApplied = allowedCidrs.scope,
                    mfaRequired = mfaRequired,
                    totpReenrollEveryLogin = totpReenrollEveryLogin,
                )
            }
        }

        return PolicyEvaluationResult(
            allowed = true, reason = null, policyScopeApplied = null,
            mfaRequired = mfaRequired, totpReenrollEveryLogin = totpReenrollEveryLogin,
        )
    }

    private data class ResolvedAttribute<T>(val value: T?, val scope: PolicyScope?)

    private fun <T> resolveAttribute(
        tenantHardCap: Boolean,
        tenantValue: T?,
        ouValue: T?,
        userValue: T?,
    ): ResolvedAttribute<T> {
        if (tenantHardCap && tenantValue != null) return ResolvedAttribute(tenantValue, PolicyScope.TENANT)
        if (userValue != null) return ResolvedAttribute(userValue, PolicyScope.USER)
        if (ouValue != null) return ResolvedAttribute(ouValue, PolicyScope.OU)
        if (tenantValue != null) return ResolvedAttribute(tenantValue, PolicyScope.TENANT)
        return ResolvedAttribute(null, null)
    }
}
