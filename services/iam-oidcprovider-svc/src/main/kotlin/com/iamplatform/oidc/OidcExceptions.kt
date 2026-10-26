package com.iamplatform.oidc

/** Raised before ever redirecting anywhere -- BUILD_PLAN.md
 * requires never redirecting an error to an unregistered/unvalidated redirect_uri. */
class InvalidAuthorizeRequestException(message: String) : RuntimeException(message)

// Added for Service 13 (iam-login-portal): POST /authorize/complete's own
// 400 case (invalid/unregistered client_id or redirect_uri, re-validated as
// defense in depth). Distinct from InvalidAuthorizeRequestException, which
// is GET /authorize's HTML-error-page case -- /authorize/complete is a
// service-to-service JSON call and must never render HTML.
class AuthorizeCompleteException(message: String) : RuntimeException(message)

// POST /authorize/complete's session-related failure: unknown/expired
// session token, or a session that doesn't belong to this client's tenant.
class SessionInvalidException(message: String) : RuntimeException(message)

class InvalidGrantException(message: String) : RuntimeException(message)

class InvalidClientException(message: String) : RuntimeException(message)
