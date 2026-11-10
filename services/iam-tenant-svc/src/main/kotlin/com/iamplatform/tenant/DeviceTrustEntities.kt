package com.iamplatform.tenant

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import java.time.Instant
import java.util.UUID

// Section 6.2 of the spec. Every transition that leaves this must publish an
// AuditEvent (see DeviceTrustService) -- never a silent status flip.
enum class DeviceLifecycleStatus {
    UNREGISTERED, AUTHENTICATION_PENDING, PENDING_APPROVAL, APPROVED,
    NON_COMPLIANT, SUSPENDED, REJECTED, REVOKED, DECOMMISSIONED,
}

enum class DeviceOwnership { CORPORATE, BYOD }
enum class DevicePlatform { WINDOWS } // macOS/Ubuntu are Phase 2 (see Section 2.1/9)
enum class ApprovalMode { AUTOMATIC, MANUAL }
enum class ApprovalDecision { APPROVED, REJECTED, SUSPENDED, REVOKED, REACTIVATED }
enum class KeyAssuranceLevel { HARDWARE_TPM, HARDWARE_CNG, SOFTWARE }
enum class KeyStatus { ACTIVE, ROTATED, REVOKED }
enum class CertificateStatus { ACTIVE, EXPIRED, REVOKED }
enum class PostureStatus { COMPLIANT, NON_COMPLIANT, UNKNOWN }
enum class HealthStatus { HEALTHY, DEGRADED, TAMPERED }
enum class FailureMode { FAIL_OPEN, FAIL_CLOSED, RISK_BASED }
enum class EventSeverity { INFO, WARNING, CRITICAL }

@Entity
@Table(name = "iam_devices")
class IamDeviceEntity(
    @Id @Column(name = "id") var id: UUID,
    @Column(name = "tenant_id", nullable = false) var tenantId: UUID,
    @Column(name = "user_id", nullable = false) var userId: UUID,
    @Column(name = "device_instance_id", nullable = false) var deviceInstanceId: UUID,
    @Column(name = "platform", nullable = false, length = 16) var platform: String = DevicePlatform.WINDOWS.name,
    @Column(name = "hostname") var hostname: String? = null,
    @Column(name = "ownership", nullable = false, length = 16) var ownership: String,
    @Column(name = "lifecycle_status", nullable = false, length = 24) var lifecycleStatus: String,
    @Column(name = "agent_version", length = 32) var agentVersion: String? = null,
    @Column(name = "created_at", nullable = false) var createdAt: Instant = Instant.now(),
    @Column(name = "updated_at", nullable = false) var updatedAt: Instant = Instant.now(),
    @Column(name = "last_seen_at") var lastSeenAt: Instant? = null,
)

@Entity
@Table(name = "iam_device_hardware")
class DeviceHardwareEntity(
    @Id @Column(name = "device_id") var deviceId: UUID,
    @Column(name = "fingerprint_version", nullable = false) var fingerprintVersion: Int,
    @Column(name = "fingerprint_hash", nullable = false, length = 128) var fingerprintHash: String,
    @Column(name = "hardware_uuid_hash", length = 128) var hardwareUuidHash: String? = null,
    @Column(name = "serial_hash", length = 128) var serialHash: String? = null,
    @Column(name = "manufacturer") var manufacturer: String? = null,
    @Column(name = "model") var model: String? = null,
    @Column(name = "os_version") var osVersion: String? = null,
)

@Entity
@Table(name = "iam_device_keys")
class DeviceKeyEntity(
    @Id @Column(name = "id") var id: UUID,
    @Column(name = "device_id", nullable = false) var deviceId: UUID,
    @Column(name = "public_key", nullable = false) var publicKey: String,
    @Column(name = "key_algorithm", nullable = false, length = 32) var keyAlgorithm: String,
    @Column(name = "assurance_level", nullable = false, length = 24) var assuranceLevel: String,
    @Column(name = "status", nullable = false, length = 16) var status: String = KeyStatus.ACTIVE.name,
    @Column(name = "created_at", nullable = false) var createdAt: Instant = Instant.now(),
    @Column(name = "rotated_at") var rotatedAt: Instant? = null,
)

@Entity
@Table(name = "iam_device_certificates")
class DeviceCertificateEntity(
    @Id @Column(name = "id") var id: UUID,
    @Column(name = "device_id", nullable = false) var deviceId: UUID,
    @Column(name = "key_id", nullable = false) var keyId: UUID,
    @Column(name = "issuer_key_id", nullable = false) var issuerKeyId: String,
    @Column(name = "serial_number", nullable = false) var serialNumber: String,
    @Column(name = "fingerprint", nullable = false, length = 128) var fingerprint: String,
    @Column(name = "not_before", nullable = false) var notBefore: Instant,
    @Column(name = "not_after", nullable = false) var notAfter: Instant,
    @Column(name = "status", nullable = false, length = 16) var status: String = CertificateStatus.ACTIVE.name,
    @Column(name = "revoked_at") var revokedAt: Instant? = null,
    @Column(name = "revoked_reason") var revokedReason: String? = null,
)

@Entity
@Table(name = "iam_device_approvals")
class DeviceApprovalEntity(
    @Id @Column(name = "id") var id: UUID,
    @Column(name = "device_id", nullable = false) var deviceId: UUID,
    @Column(name = "approval_mode", nullable = false, length = 16) var approvalMode: String,
    @Column(name = "decision", nullable = false, length = 16) var decision: String,
    @Column(name = "actor_id", nullable = false) var actorId: String,
    @Column(name = "reason") var reason: String? = null,
    @Column(name = "decided_at", nullable = false) var decidedAt: Instant = Instant.now(),
)

@Entity
@Table(name = "iam_device_posture")
class DevicePostureEntity(
    @Id @Column(name = "device_id") var deviceId: UUID,
    @Column(name = "posture_status", nullable = false, length = 16) var postureStatus: String,
    @Column(name = "risk_score") var riskScore: Int? = null,
    @Column(name = "signals_json") var signalsJson: String? = null,
    @Column(name = "evaluated_at", nullable = false) var evaluatedAt: Instant = Instant.now(),
)

@Entity
@Table(name = "iam_device_heartbeats")
class DeviceHeartbeatEntity(
    @Id @Column(name = "device_id") var deviceId: UUID,
    @Column(name = "last_seen_at", nullable = false) var lastSeenAt: Instant = Instant.now(),
    @Column(name = "agent_version", nullable = false, length = 32) var agentVersion: String,
    @Column(name = "policy_version", nullable = false) var policyVersion: Int,
    @Column(name = "health_status", nullable = false, length = 16) var healthStatus: String,
)

@Entity
@Table(name = "iam_device_events")
class DeviceEventEntity(
    @Id @Column(name = "id") var id: UUID,
    @Column(name = "tenant_id", nullable = false) var tenantId: UUID,
    @Column(name = "device_id", nullable = false) var deviceId: UUID,
    @Column(name = "event_type", nullable = false, length = 64) var eventType: String,
    @Column(name = "severity", nullable = false, length = 16) var severity: String,
    @Column(name = "metadata_json") var metadataJson: String? = null,
    @Column(name = "occurred_at", nullable = false) var occurredAt: Instant = Instant.now(),
)

@Entity
@Table(name = "iam_device_policies")
class DevicePolicyEntity(
    @Id @Column(name = "id") var id: UUID,
    @Column(name = "tenant_id", nullable = false) var tenantId: UUID,
    @Column(name = "name", nullable = false) var name: String,
    @Column(name = "version", nullable = false) var version: Int,
    @Column(name = "configuration_json", nullable = false) var configurationJson: String,
    @Column(name = "signature") var signature: String? = null,
    @Column(name = "effective_at", nullable = false) var effectiveAt: Instant = Instant.now(),
)

@Entity
@Table(name = "iam_device_app_policies")
class DeviceAppPolicyEntity(
    @Id @Column(name = "id") var id: UUID,
    @Column(name = "policy_id", nullable = false) var policyId: UUID,
    @Column(name = "application_id", nullable = false) var applicationId: UUID,
    @Column(name = "pending_access", nullable = false) var pendingAccess: Boolean = false,
    @Column(name = "offline_access", nullable = false) var offlineAccess: Boolean = false,
    @Column(name = "offline_grace_seconds", nullable = false) var offlineGraceSeconds: Int = 0,
    @Column(name = "failure_mode", nullable = false, length = 16) var failureMode: String = FailureMode.RISK_BASED.name,
)

@Entity
@Table(name = "iam_device_enrollment_transactions")
class DeviceEnrollmentTransactionEntity(
    @Id @Column(name = "id") var id: UUID,
    @Column(name = "tenant_id", nullable = false) var tenantId: UUID,
    @Column(name = "user_id", nullable = false) var userId: UUID,
    @Column(name = "nonce", nullable = false) var nonce: String,
    @Column(name = "created_at", nullable = false) var createdAt: Instant = Instant.now(),
    @Column(name = "expires_at", nullable = false) var expiresAt: Instant,
    @Column(name = "consumed_at") var consumedAt: Instant? = null,
    @Column(name = "key_thumbprint", length = 64) var keyThumbprint: String? = null,
)

interface IamDeviceRepository : JpaRepository<IamDeviceEntity, UUID> {
    fun findByTenantIdAndDeviceInstanceId(tenantId: UUID, deviceInstanceId: UUID): IamDeviceEntity?
    fun findByTenantId(tenantId: UUID): List<IamDeviceEntity>
    fun countByTenantIdAndUserIdAndLifecycleStatusNotIn(tenantId: UUID, userId: UUID, excluded: List<String>): Long
}

interface DeviceHardwareRepository : JpaRepository<DeviceHardwareEntity, UUID>

interface DeviceKeyRepository : JpaRepository<DeviceKeyEntity, UUID> {
    fun findByDeviceIdAndStatus(deviceId: UUID, status: String): DeviceKeyEntity?
}

interface DeviceCertificateRepository : JpaRepository<DeviceCertificateEntity, UUID> {
    fun findByDeviceIdAndStatus(deviceId: UUID, status: String): DeviceCertificateEntity?
    fun findBySerialNumber(serialNumber: String): DeviceCertificateEntity?
}

interface DeviceApprovalRepository : JpaRepository<DeviceApprovalEntity, UUID> {
    fun findByDeviceIdOrderByDecidedAtDesc(deviceId: UUID): List<DeviceApprovalEntity>
}

interface DevicePostureRepository : JpaRepository<DevicePostureEntity, UUID>
interface DeviceHeartbeatRepository : JpaRepository<DeviceHeartbeatEntity, UUID>

interface DeviceEventRepository : JpaRepository<DeviceEventEntity, UUID> {
    fun findByDeviceIdOrderByOccurredAtDesc(deviceId: UUID): List<DeviceEventEntity>
}

interface DevicePolicyRepository : JpaRepository<DevicePolicyEntity, UUID> {
    fun findTopByTenantIdOrderByVersionDesc(tenantId: UUID): DevicePolicyEntity?
}

interface DeviceAppPolicyRepository : JpaRepository<DeviceAppPolicyEntity, UUID> {
    fun findByPolicyId(policyId: UUID): List<DeviceAppPolicyEntity>
}

interface DeviceEnrollmentTransactionRepository : JpaRepository<DeviceEnrollmentTransactionEntity, UUID>

class DeviceNotFoundException(id: UUID) : RuntimeException("No device '$id' found for this tenant")
class EnrollmentTransactionInvalidException(message: String) : RuntimeException(message)
class DeviceProofOfPossessionException(message: String) : RuntimeException(message)
class DeviceLimitExceededException(message: String) : RuntimeException(message)
