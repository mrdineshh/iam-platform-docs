package com.iamplatform.tenant

import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.NotNull
import jakarta.validation.constraints.Size
import java.time.Instant
import java.util.UUID

data class CreateSamlSpRequest(
    @field:NotNull
    val tenantId: UUID,

    @field:NotBlank
    @field:Size(max = 255)
    val name: String,

    @field:NotBlank
    @field:Size(max = 512)
    val spEntityId: String,

    @field:NotBlank
    @field:Size(max = 1024)
    val acsUrl: String,

    val launchUrl: String? = null,
)

data class SamlSpResponse(
    val id: UUID,
    val tenantId: UUID,
    val name: String,
    val spEntityId: String,
    val acsUrl: String,
    val launchUrl: String?,
    val createdAt: Instant,
)

fun SamlSpEntity.toResponse(): SamlSpResponse =
    SamlSpResponse(
        id = id,
        tenantId = tenantId,
        name = name,
        spEntityId = spEntityId,
        acsUrl = acsUrl,
        launchUrl = launchUrl,
        createdAt = createdAt,
    )

class SamlSpNotFoundException(id: UUID) : RuntimeException("No SAML SP with id $id")

class SamlSpEntityIdAlreadyExistsException(spEntityId: String) :
    RuntimeException("A SAML SP with entity ID '$spEntityId' is already registered")
