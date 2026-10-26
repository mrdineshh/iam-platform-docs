package com.iamplatform.tenant

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import java.time.Instant
import java.util.UUID

data class CreateTenantRequest(
    @field:NotBlank
    @field:Size(max = 255)
    val name: String,

    @field:NotBlank
    @field:Pattern(regexp = "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
    val subdomain: String,
)

data class TenantResponse(
    val id: UUID,
    val name: String,
    val subdomain: String,
    val status: TenantStatus,
    val createdAt: Instant,
)

fun TenantEntity.toResponse(): TenantResponse =
    TenantResponse(
        id = id,
        name = name,
        subdomain = subdomain,
        status = status,
        createdAt = createdAt,
    )
