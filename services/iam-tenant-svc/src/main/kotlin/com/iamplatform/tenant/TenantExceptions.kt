package com.iamplatform.tenant

import java.util.UUID

class TenantNotFoundException(id: UUID) : RuntimeException("No tenant with id $id")

class TenantSubdomainNotFoundException(subdomain: String) :
    RuntimeException("No tenant with subdomain '$subdomain'")

class SubdomainAlreadyExistsException(subdomain: String) :
    RuntimeException("Subdomain '$subdomain' is already in use")
