package com.iamplatform.identity

import jakarta.validation.Valid
import org.springframework.http.HttpStatus
import org.springframework.http.ResponseEntity
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.util.UUID

/**
 * Groups back a user to a PolicyScope.OU entry (iam-policy-svc) -- a
 * group IS an OU for policy purposes, not a separate concept. Unauthenticated
 * at this layer like every other endpoint here (mTLS-only inbound,
 * admin-gating happens at iam-tenant-svc's proxy).
 */
@RestController
@RequestMapping("/api/v1/groups")
class GroupController(
    private val groupService: GroupService,
) {
    @PostMapping
    fun createGroup(@Valid @RequestBody request: CreateGroupRequest): ResponseEntity<GroupResponse> =
        ResponseEntity.status(HttpStatus.CREATED).body(groupService.createGroup(request).toResponse())

    @GetMapping
    fun listGroups(@RequestParam tenantId: UUID): ResponseEntity<List<GroupResponse>> =
        ResponseEntity.ok(groupService.listGroups(tenantId).map { it.toResponse() })

    @DeleteMapping("/{id}")
    fun deleteGroup(@PathVariable id: UUID): ResponseEntity<Void> {
        groupService.deleteGroup(id)
        return ResponseEntity.noContent().build()
    }
}
