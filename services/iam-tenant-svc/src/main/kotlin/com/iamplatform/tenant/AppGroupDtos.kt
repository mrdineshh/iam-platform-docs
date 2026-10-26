package com.iamplatform.tenant

import jakarta.validation.constraints.NotNull
import java.util.UUID

/** Shared by OidcClientController and SamlSpController's `/groups` endpoints. */
data class UpdateAppGroupsRequest(
    @field:NotNull
    val groupIds: List<UUID>,
)

data class AppGroupsResponse(
    val groupIds: List<UUID>,
)
