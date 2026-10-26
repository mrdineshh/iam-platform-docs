package com.iamplatform.tenant

import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Size
import java.util.UUID

data class CreateUserRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    @field:Email
    val email: String,

    @field:NotBlank
    val displayName: String,

    @field:Size(min = 8)
    val password: String? = null,

    val role: RemoteUserRole? = null,

    // Added 2026-10-26 (docs/DECISIONS.md) so this is a visible, per-user
    // choice rather than silent automatic behavior whenever Google
    // Workspace happens to be configured for the tenant. Default true so
    // existing callers (and the common case) keep working unchanged.
    val createInGoogleWorkspace: Boolean = true,
)

data class CreatedUserResponse(
    val id: UUID,
    val tenantId: UUID,
    val email: String,
    val displayName: String,
    val role: RemoteUserRole,
    // Shown once, same "never retrievable again" contract as device-svc's
    // own EnrollDeviceResponse -- the admin must hand these to the new
    // user right now (screen share, printout, etc.), not store them.
    val totpSecret: String,
    val provisioningUri: String,
    // Whether this tenant has Google Workspace auto-provisioning
    // configured and it succeeded. Deliberately never fails user creation
    // itself -- see AdminUserController's comment on why this is
    // best-effort, not a hard dependency of the core flow.
    val googleWorkspaceProvisioned: Boolean = false,
    val googleWorkspaceError: String? = null,
)

data class Enroll2faResponse(
    val deviceId: UUID,
    val status: String,
    val totpSecret: String,
    val provisioningUri: String,
)

data class Verify2faRequest(
    @field:NotBlank
    @field:jakarta.validation.constraints.Pattern(regexp = "^\\d{6}$")
    val code: String,
)

data class Verify2faResponse(val valid: Boolean, val status: String)

data class DeletedUserResponse(
    val id: UUID,
    val googleWorkspaceDeleted: Boolean = false,
    val googleWorkspaceError: String? = null,
)

class UserNotFoundForDeletionException(id: UUID) : RuntimeException("No user '$id' found for this tenant")
