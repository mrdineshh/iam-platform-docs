package com.iamplatform.tenant

import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

data class MeResponse(
    val id: UUID,
    val tenantId: UUID,
    val email: String?,
    val displayName: String?,
    val role: RemoteUserRole,
)

/**
 * "Who is signed in" for the person holding the session token: shown in the
 * launchpad's account menu. Session-gated only (any signed-in user), and it can
 * only ever describe the caller's own account -- the user id comes from the
 * session, never from the request.
 */
@RestController
@RequestMapping("/api/v1/me")
class MeController(
    private val adminAccessGuard: AdminAccessGuard,
    private val identityClient: IdentityClient,
) {
    @GetMapping
    fun me(@RequestHeader("X-Session-Token") sessionToken: String): ResponseEntity<MeResponse> {
        val session = adminAccessGuard.requireValidSession(sessionToken)
        // The session outliving its user (deleted mid-session) reads as an invalid session.
        val user = identityClient.findUser(session.userId) ?: throw AdminSessionInvalidException()
        return ResponseEntity.ok(MeResponse(user.id, user.tenantId, user.email, user.displayName, user.role))
    }
}
