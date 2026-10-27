package com.iamplatform.policy

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant
import java.util.UUID

enum class PolicyScope { TENANT, OU, USER }

/**
 * Countries are stored as a comma-joined string rather than a Postgres
 * array/JSONB column -- there are only two list attributes in the MVP
 * schema, and this avoids any Hibernate array-type mapping fragility for a
 * shape this simple. See [allowedCountriesList] / [blockedCountriesList].
 */
@Entity
@Table(name = "policies")
class PolicyEntity(
    @Id
    @Column(name = "id")
    var id: UUID,

    @Column(name = "tenant_id", nullable = false)
    var tenantId: UUID,

    @Enumerated(EnumType.STRING)
    @Column(name = "scope", nullable = false, length = 16)
    var scope: PolicyScope,

    @Column(name = "scope_id", nullable = false)
    var scopeId: UUID,

    @Column(name = "allowed_countries")
    var allowedCountries: String? = null,

    @Column(name = "allowed_countries_hard_cap", nullable = false)
    var allowedCountriesHardCap: Boolean = false,

    @Column(name = "blocked_countries")
    var blockedCountries: String? = null,

    @Column(name = "blocked_countries_hard_cap", nullable = false)
    var blockedCountriesHardCap: Boolean = false,

    @Column(name = "allowed_cidrs")
    var allowedCidrs: String? = null,

    @Column(name = "allowed_cidrs_hard_cap", nullable = false)
    var allowedCidrsHardCap: Boolean = false,

    @Column(name = "blocked_cidrs")
    var blockedCidrs: String? = null,

    @Column(name = "blocked_cidrs_hard_cap", nullable = false)
    var blockedCidrsHardCap: Boolean = false,

    // Nullable -- see migration comment. Whether 2FA is required at login
    // for whoever this policy scope applies to.
    @Column(name = "mfa_required")
    var mfaRequired: Boolean? = null,

    @Column(name = "mfa_required_hard_cap", nullable = false)
    var mfaRequiredHardCap: Boolean = false,

    // When true, a fresh login (no code submitted yet) always resets the
    // user's TOTP device and issues a brand-new QR, even if one was already
    // active -- instead of the default "enroll once, keep using it" (see
    // iam-device-svc's resetAndEnroll vs ensurePending). Nullable, default
    // resolves to false -- never fail open here, but "false" IS the normal/
    // safe default (persistent device), unlike mfaRequired's "true" default.
    @Column(name = "totp_reenroll_every_login")
    var totpReenrollEveryLogin: Boolean? = null,

    @Column(name = "totp_reenroll_every_login_hard_cap", nullable = false)
    var totpReenrollEveryLoginHardCap: Boolean = false,

    // Tenant-scope-only sign-in security settings (FR-3.1, FR-3.5); null =
    // platform default. See PolicyService.securitySettings.
    @Column(name = "password_min_length")
    var passwordMinLength: Int? = null,

    @Column(name = "password_require_uppercase")
    var passwordRequireUppercase: Boolean? = null,

    @Column(name = "password_require_lowercase")
    var passwordRequireLowercase: Boolean? = null,

    @Column(name = "password_require_digit")
    var passwordRequireDigit: Boolean? = null,

    @Column(name = "password_require_symbol")
    var passwordRequireSymbol: Boolean? = null,

    @Column(name = "lockout_threshold")
    var lockoutThreshold: Int? = null,

    @Column(name = "lockout_duration_minutes")
    var lockoutDurationMinutes: Int? = null,

    @Column(name = "lockout_permanent")
    var lockoutPermanent: Boolean? = null,

    @Column(name = "updated_at", nullable = false)
    var updatedAt: Instant = Instant.now(),
) {
    val allowedCountriesList: List<String>?
        get() = allowedCountries?.split(",")?.map { it.trim() }?.filter { it.isNotBlank() }?.takeIf { it.isNotEmpty() }

    val blockedCountriesList: List<String>?
        get() = blockedCountries?.split(",")?.map { it.trim() }?.filter { it.isNotBlank() }?.takeIf { it.isNotEmpty() }

    val allowedCidrsList: List<String>?
        get() = allowedCidrs?.split(",")?.map { it.trim() }?.filter { it.isNotBlank() }?.takeIf { it.isNotEmpty() }

    val blockedCidrsList: List<String>?
        get() = blockedCidrs?.split(",")?.map { it.trim() }?.filter { it.isNotBlank() }?.takeIf { it.isNotEmpty() }
}

fun List<String>?.toCsv(): String? = this?.joinToString(",")?.takeIf { it.isNotBlank() }
