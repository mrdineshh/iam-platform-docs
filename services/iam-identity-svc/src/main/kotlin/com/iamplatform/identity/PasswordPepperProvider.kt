package com.iamplatform.identity

import com.iamplatform.servicekit.vault.OpenBaoClient
import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.Base64

/**
 * MVP-TEMPORARY (docs/DECISIONS.md, Service 7 entry): a single platform-wide
 * pepper stored as a plain OpenBao KV v2 secret, not a per-tenant pepper via
 * OpenBao Transit's HMAC operation as originally decided during the Module 1
 * interview (2026-08-03). Transit needs bootstrap tooling (enabling the
 * engine, creating a key) this MVP doesn't have yet, and there is no
 * tenant-onboarding flow to provision a pepper per tenant. Get-or-create: the
 * first service instance to ask for the pepper generates and persists it, so
 * this works against OpenBao's ephemeral dev-mode container with no manual
 * seeding step.
 */
@Component
class PasswordPepperProvider(
    private val openBaoClient: OpenBaoClient,
) {
    @Volatile
    private var cached: String? = null

    fun get(): String {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val pepper = openBaoClient.readSecretOrNull(PEPPER_PATH)?.get("value") as? String
                ?: generateAndStore()
            cached = pepper
            return pepper
        }
    }

    private fun generateAndStore(): String {
        val bytes = ByteArray(32)
        SecureRandom().nextBytes(bytes)
        val pepper = Base64.getEncoder().encodeToString(bytes)
        openBaoClient.writeSecret(PEPPER_PATH, mapOf("value" to pepper))
        return pepper
    }

    companion object {
        private const val PEPPER_PATH = "password-pepper"
    }
}
