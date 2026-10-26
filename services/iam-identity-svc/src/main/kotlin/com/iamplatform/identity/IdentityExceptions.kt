package com.iamplatform.identity

import java.util.UUID

class UserNotFoundException(id: UUID) : RuntimeException("No user with id $id")

class EmailAlreadyExistsException(email: String) :
    RuntimeException("Email '$email' is already in use within this tenant")

class TenantNotFoundException(tenantId: UUID) : RuntimeException("No tenant with id $tenantId")
