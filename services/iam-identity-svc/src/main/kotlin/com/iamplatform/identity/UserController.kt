package com.iamplatform.identity

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PatchMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

@RestController
@RequestMapping("/api/v1/users")
class UserController(
    private val userService: UserService,
) {

    @PostMapping
    fun createUser(@Valid @RequestBody request: CreateUserRequest): ResponseEntity<UserResponse> =
        ResponseEntity.status(HttpStatus.CREATED).body(userService.createUser(request).toResponse())

    // Added for the admin-console "Switch to user" picker. Unauthenticated at
    // this layer, same as every other endpoint here -- this service is
    // mTLS-only inbound (no browser can reach it directly) and the real
    // admin-gating happens at iam-tenant-svc's proxy (AdminAccessGuard),
    // matching the existing createUser/updateRole pattern.
    @GetMapping
    fun listUsers(@RequestParam tenantId: UUID): ResponseEntity<List<UserResponse>> =
        ResponseEntity.ok(userService.listUsers(tenantId).map { it.toResponse() })

    @GetMapping("/{id}")
    fun getUser(@PathVariable id: UUID): ResponseEntity<UserResponse> =
        ResponseEntity.ok(userService.getUser(id).toResponse())

    @PatchMapping("/{id}/status")
    fun updateStatus(
        @PathVariable id: UUID,
        @Valid @RequestBody request: UpdateStatusRequest,
    ): ResponseEntity<UserResponse> =
        ResponseEntity.ok(userService.updateStatus(id, request).toResponse())

    @PatchMapping("/{id}/role")
    fun updateRole(
        @PathVariable id: UUID,
        @Valid @RequestBody request: UpdateRoleRequest,
    ): ResponseEntity<UserResponse> =
        ResponseEntity.ok(userService.updateRole(id, request).toResponse())

    // Added for group-based policy (2FA requirement, IP allowlisting).
    @PatchMapping("/{id}/group")
    fun assignGroup(
        @PathVariable id: UUID,
        @Valid @RequestBody request: AssignGroupRequest,
    ): ResponseEntity<UserResponse> =
        ResponseEntity.ok(userService.assignGroup(id, request).toResponse())

    @PatchMapping("/{id}/password")
    fun setPassword(
        @PathVariable id: UUID,
        @Valid @RequestBody request: SetPasswordRequest,
    ): ResponseEntity<Void> {
        userService.setPassword(id, request)
        return ResponseEntity.noContent().build()
    }

    // Returns the deleted user's own data (including email) -- the caller
    // (iam-tenant-svc) needs the email to also delete the matching Google
    // Workspace account, and there's no point making it fetch the user
    // separately first just to learn what it's about to delete.
    @DeleteMapping("/{id}")
    fun deleteUser(@PathVariable id: UUID): ResponseEntity<UserResponse> =
        ResponseEntity.ok(userService.deleteUser(id).toResponse())

    // Admin-initiated (the admin is gated and audited at iam-tenant-svc's proxy).
    @PostMapping("/{id}/unlock")
    fun unlockUser(@PathVariable id: UUID): ResponseEntity<UserResponse> =
        ResponseEntity.ok(userService.unlockUser(id).toResponse())

    @PostMapping("/verify-password")
    fun verifyPassword(@Valid @RequestBody request: VerifyPasswordRequest): ResponseEntity<VerifyPasswordResponse> =
        ResponseEntity.ok(userService.verifyPassword(request))
}
