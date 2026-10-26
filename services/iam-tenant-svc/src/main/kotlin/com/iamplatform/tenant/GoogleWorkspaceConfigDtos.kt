package com.iamplatform.tenant

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import java.time.Instant
import java.util.UUID

data class SetGoogleWorkspaceConfigRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    val domain: String,

    @field:NotBlank
    val adminEmail: String,

    val orgUnitPath: String? = null,

    // The raw contents of the service account's downloaded JSON key file,
    // pasted whole -- parsed here, never persisted as-is (the private key
    // goes to OpenBao; nothing from it is ever echoed back in any response).
    @field:NotBlank
    val serviceAccountJson: String,
)

/**
 * Deliberately never includes the service account key or any secret --
 * same "write-only credential" shape as OidcClientResponse's client secret
 * (shown once at creation, never GET-able again). `configured` is what the
 * admin console's "Add User" flow checks to decide whether to even offer
 * Google auto-provisioning as an option.
 */
data class GoogleWorkspaceConfigResponse(
    val tenantId: UUID,
    val domain: String,
    val adminEmail: String,
    val orgUnitPath: String?,
    val configured: Boolean,
    val createdAt: Instant,
)

class GoogleWorkspaceConfigNotFoundException(tenantId: UUID) :
    RuntimeException("No Google Workspace configuration for tenant '$tenantId'")

class InvalidServiceAccountJsonException(reason: String) :
    RuntimeException("Invalid Google service account JSON: $reason")

fun GoogleWorkspaceConfigEntity.toResponse() = GoogleWorkspaceConfigResponse(
    tenantId = tenantId,
    domain = domain,
    adminEmail = adminEmail,
    orgUnitPath = orgUnitPath,
    configured = true,
    createdAt = createdAt,
)
