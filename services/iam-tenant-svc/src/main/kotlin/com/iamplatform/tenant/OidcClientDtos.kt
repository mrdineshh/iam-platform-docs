package com.iamplatform.tenant

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotEmpty
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Size
import java.time.Instant
import java.util.UUID

data class CreateOidcClientRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    @field:Size(max = 255)
    val name: String,

    @field:NotEmpty
    val redirectUris: List<String>,

    // See OidcClientEntity.launchUrl -- optional, this app just won't
    // appear on the launchpad if omitted.
    val launchUrl: String? = null,
)

data class OidcClientResponse(
    val clientId: UUID,
    val tenantId: UUID,
    val name: String,
    val redirectUris: List<String>,
    val launchUrl: String?,
    val createdAt: Instant,
)

data class CreatedOidcClientResponse(
    val clientId: UUID,
    val clientSecret: String,
    val tenantId: UUID,
    val name: String,
    val redirectUris: List<String>,
    val launchUrl: String?,
    val createdAt: Instant,
)

fun OidcClientEntity.toResponse(): OidcClientResponse =
    OidcClientResponse(
        clientId = id,
        tenantId = tenantId,
        name = name,
        redirectUris = redirectUriList,
        launchUrl = launchUrl,
        createdAt = createdAt,
    )

data class VerifyClientSecretRequest(
    @field:NotBlank
    val clientSecret: String,
)

data class VerifyClientSecretResponse(
    val valid: Boolean,
    val tenantId: UUID? = null,
)

class OidcClientNotFoundException(id: UUID) : RuntimeException("No OIDC client with id $id")
