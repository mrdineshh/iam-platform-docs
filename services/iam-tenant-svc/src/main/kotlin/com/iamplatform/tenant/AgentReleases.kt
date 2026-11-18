package com.iamplatform.tenant

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.http.ResponseEntity
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestHeader
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.UUID

/*
 * Signed agent updates (docs/specs/agent-update-SPEC.md, P1-26). This service only STORES and SERVES releases. It cannot sign one:
 * the operator signs with the OpenBao `agent-release` key at publish time, and the agent verifies that signature itself before
 * installing. So this file deliberately contains no signing and does not need to trust its own inputs beyond the checksum.
 */

@Entity
@Table(name = "iam_agent_releases")
class AgentReleaseEntity(
    @Id @Column(name = "id") var id: UUID,
    @Column(name = "version", nullable = false, length = 32) var version: String,
    @Column(name = "platform", nullable = false, length = 16) var platform: String,
    @Column(name = "architecture", nullable = false, length = 16) var architecture: String,
    @Column(name = "package_uri", nullable = false, length = 1024) var packageUri: String,
    @Column(name = "checksum", nullable = false, length = 128) var checksum: String,
    @Column(name = "signing_key_id", nullable = false) var signingKeyId: String,
    @Column(name = "release_state", nullable = false, length = 16) var releaseState: String,
    @Column(name = "signature") var signature: String? = null,
    @Column(name = "created_at", nullable = false) var createdAt: Instant = Instant.now(),
)

@Entity
@Table(name = "iam_agent_release_packages")
class AgentReleasePackageEntity(
    @Id @Column(name = "release_id") var releaseId: UUID,
    @Column(name = "content", nullable = false) var content: ByteArray,
    @Column(name = "size_bytes", nullable = false) var sizeBytes: Long,
)

interface AgentReleaseRepository : JpaRepository<AgentReleaseEntity, UUID> {
    fun findByPlatformAndArchitectureAndReleaseState(platform: String, architecture: String, releaseState: String): List<AgentReleaseEntity>
    fun existsByVersionAndPlatformAndArchitecture(version: String, platform: String, architecture: String): Boolean
}

interface AgentReleasePackageRepository : JpaRepository<AgentReleasePackageEntity, UUID>

data class PublishAgentReleaseRequest(
    @field:Pattern(regexp = "^\\d{1,4}\\.\\d{1,4}\\.\\d{1,6}$") val version: String,
    @field:Pattern(regexp = "^WINDOWS$") val platform: String,
    @field:Pattern(regexp = "^(x86_64|aarch64)$") val architecture: String,
    @field:Pattern(regexp = "^[0-9a-f]{64}$") val sha256: String,
    @field:NotBlank val signature: String,
    @field:Pattern(regexp = "^(DRAFT|PILOT|PRODUCTION|RETIRED)$") val releaseState: String,
    @field:NotBlank val contentBase64: String,
)

data class AgentReleaseOffer(
    val releaseId: UUID,
    val version: String,
    val platform: String,
    val architecture: String,
    val sha256: String,
    val signature: String,
    val sizeBytes: Long,
)

class AgentReleaseRejectedException(message: String) : RuntimeException(message)

/** Semantic version order for plain x.y.z versions. Anything unparseable sorts lowest (and is never offered as an upgrade). */
object AgentVersions {
    fun parse(v: String): List<Int>? = v.trim().split('.').takeIf { it.size == 3 }?.map { it.toIntOrNull() ?: return null }

    fun isNewer(candidate: String, current: String): Boolean {
        val a = parse(candidate) ?: return false
        val b = parse(current) ?: return true
        for (i in 0..2) if (a[i] != b[i]) return a[i] > b[i]
        return false
    }
}

@Service
class AgentReleaseService(
    private val releases: AgentReleaseRepository,
    private val packages: AgentReleasePackageRepository,
) {
    @Transactional
    fun publish(request: PublishAgentReleaseRequest): AgentReleaseOffer {
        val content = try {
            Base64.getDecoder().decode(request.contentBase64)
        } catch (ex: IllegalArgumentException) {
            throw AgentReleaseRejectedException("content is not valid base64")
        }
        if (content.isEmpty() || content.size > MAX_PACKAGE_BYTES) throw AgentReleaseRejectedException("package size ${content.size} not accepted")
        val actual = MessageDigest.getInstance("SHA-256").digest(content).joinToString("") { "%02x".format(it) }
        if (actual != request.sha256) throw AgentReleaseRejectedException("sha256 does not match the uploaded package")
        if (releases.existsByVersionAndPlatformAndArchitecture(request.version, request.platform, request.architecture)) {
            throw AgentReleaseRejectedException("version ${request.version} already published for ${request.platform}/${request.architecture}")
        }
        val id = UUID.randomUUID()
        val entity = AgentReleaseEntity(
            id = id,
            version = request.version,
            platform = request.platform,
            architecture = request.architecture,
            packageUri = "db:iam_agent_release_packages/$id",
            checksum = request.sha256,
            signingKeyId = SIGNING_KEY_ID,
            releaseState = request.releaseState,
            signature = request.signature,
        )
        releases.save(entity)
        packages.save(AgentReleasePackageEntity(id, content, content.size.toLong()))
        return entity.toOffer(content.size.toLong())
    }

    /** The newest PRODUCTION release newer than `currentVersion`, or null. */
    fun offerFor(platform: String, architecture: String, currentVersion: String): AgentReleaseOffer? {
        val best = releases.findByPlatformAndArchitectureAndReleaseState(platform, architecture, "PRODUCTION")
            .filter { it.signature != null && AgentVersions.isNewer(it.version, currentVersion) }
            .maxWithOrNull { a, b -> if (AgentVersions.isNewer(a.version, b.version)) 1 else if (AgentVersions.isNewer(b.version, a.version)) -1 else 0 }
            ?: return null
        val size = packages.findById(best.id).map { it.sizeBytes }.orElse(0L)
        if (size == 0L) return null
        return best.toOffer(size)
    }

    fun packageBytes(releaseId: UUID): ByteArray? = packages.findById(releaseId).map { it.content }.orElse(null)

    private fun AgentReleaseEntity.toOffer(size: Long) = AgentReleaseOffer(id, version, platform, architecture, checksum, signature!!, size)

    companion object {
        const val MAX_PACKAGE_BYTES = 64 * 1024 * 1024
        const val SIGNING_KEY_ID = "openbao:transit/agent-release"
    }
}

/** Operator-only (InternalOnlyFilter answers 404 to anything that came through the public proxy). */
@RestController
@RequestMapping("/internal/agent-releases")
class InternalAgentReleaseController(private val service: AgentReleaseService) {
    @PostMapping
    fun publish(@Valid @RequestBody request: PublishAgentReleaseRequest): ResponseEntity<Any> =
        try {
            ResponseEntity.status(HttpStatus.CREATED).body(service.publish(request))
        } catch (ex: AgentReleaseRejectedException) {
            ResponseEntity.badRequest().body(mapOf("error" to ex.message))
        }
}

/** Agent-facing, device-authenticated exactly like the policy fetch. */
@RestController
@RequestMapping("/api/v1/endpoint/devices/{deviceId}")
class AgentUpdateController(
    private val deviceTrustService: DeviceTrustService,
    private val service: AgentReleaseService,
) {
    @GetMapping("/agent-update")
    fun offer(
        @PathVariable deviceId: UUID,
        @RequestParam tenantId: UUID,
        @RequestParam currentVersion: String,
        @RequestHeader("X-Device-Signature") signature: String,
        @RequestHeader("X-Device-Timestamp") timestamp: String,
    ): ResponseEntity<AgentReleaseOffer> {
        deviceTrustService.requireDeviceProof(tenantId, deviceId, parseTimestamp(timestamp), signature)
        val offer = service.offerFor("WINDOWS", "x86_64", currentVersion) ?: return ResponseEntity.noContent().build()
        return ResponseEntity.ok(offer)
    }

    @GetMapping("/agent-releases/{releaseId}/package")
    fun download(
        @PathVariable deviceId: UUID,
        @PathVariable releaseId: UUID,
        @RequestParam tenantId: UUID,
        @RequestHeader("X-Device-Signature") signature: String,
        @RequestHeader("X-Device-Timestamp") timestamp: String,
    ): ResponseEntity<ByteArray> {
        deviceTrustService.requireDeviceProof(tenantId, deviceId, parseTimestamp(timestamp), signature)
        val bytes = service.packageBytes(releaseId) ?: return ResponseEntity.notFound().build()
        return ResponseEntity.ok()
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .header(HttpHeaders.CACHE_CONTROL, "no-store")
            .body(bytes)
    }

    private fun parseTimestamp(value: String): Instant =
        try {
            Instant.parse(value)
        } catch (ex: Exception) {
            throw DeviceProofOfPossessionException("Malformed X-Device-Timestamp header")
        }
}
