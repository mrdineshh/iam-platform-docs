package com.iamplatform.device.crypto

import com.iamplatform.servicekit.vault.OpenBaoClient
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Per-tenant AES-256 data-encryption key for TOTP secrets (BUILD_PLAN.md
 * Service 9: "AES-256-GCM, per-tenant DEK from OpenBao"). Get-or-create
 * against OpenBao's KV v2 engine -- same pattern as iam-identity-svc's
 * PasswordPepperProvider (docs/DECISIONS.md, Service 7 entry), just keyed
 * per-tenant instead of platform-wide. Not routed through OpenBao Transit:
 * BUILD_PLAN only requires the key be OpenBao-held, and Transit still has no
 * bootstrap tooling in this MVP (same reasoning as the pepper's deviation).
 */
@Component
class TotpDekProvider(
    private val openBaoClient: OpenBaoClient,
) {
    private val cache = ConcurrentHashMap<UUID, ByteArray>()

    fun get(tenantId: UUID): ByteArray =
        cache.computeIfAbsent(tenantId) { id ->
            val existing = openBaoClient.readSecretOrNull(pathFor(id))?.get("value") as? String
            if (existing != null) {
                Base64.getDecoder().decode(existing)
            } else {
                generateAndStore(id)
            }
        }

    private fun generateAndStore(tenantId: UUID): ByteArray {
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        openBaoClient.writeSecret(pathFor(tenantId), mapOf("value" to Base64.getEncoder().encodeToString(key)))
        return key
    }

    private fun pathFor(tenantId: UUID) = "totp-dek/$tenantId"
}
