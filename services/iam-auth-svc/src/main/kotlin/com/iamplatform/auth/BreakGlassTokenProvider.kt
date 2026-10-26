package com.iamplatform.auth

import com.iamplatform.servicekit.vault.OpenBaoClient
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

/**
 * Per-tenant break-glass token for AP-8's break-glass requirement -- the
 * one path that can reset ANY user's (including the only admin's) 2FA
 * without a valid session, for the "locked out, nobody left to fix it"
 * case. Get-or-create against OpenBao, same pattern as
 * iam-device-svc's TotpDekProvider: generated once on first use, then
 * stable. Deliberately not surfaced through any admin-console UI or
 * API response -- an operator retrieves it directly from OpenBao
 * (`bao kv get secret/break-glass-token/<tenantId>`), which is the point:
 * this requires infrastructure-level access, not just an app-level admin
 * session, exactly like a physical break-glass key.
 */
@Component
class BreakGlassTokenProvider(
    private val openBaoClient: OpenBaoClient,
) {
    private val cache = ConcurrentHashMap<UUID, String>()

    fun get(tenantId: UUID): String =
        cache.computeIfAbsent(tenantId) { id ->
            val existing = openBaoClient.readSecretOrNull(pathFor(id))?.get("value") as? String
            existing ?: generateAndStore(id)
        }

    fun matches(tenantId: UUID, candidate: String): Boolean = get(tenantId) == candidate

    private fun generateAndStore(tenantId: UUID): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        val token = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        openBaoClient.writeSecret(pathFor(tenantId), mapOf("value" to token))
        return token
    }

    private fun pathFor(tenantId: UUID) = "break-glass-token/$tenantId"
}
