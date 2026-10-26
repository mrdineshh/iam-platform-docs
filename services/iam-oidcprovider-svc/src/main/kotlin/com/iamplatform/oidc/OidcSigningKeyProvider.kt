package com.iamplatform.oidc

import com.iamplatform.servicekit.vault.OpenBaoClient
import com.nimbusds.jose.jwk.RSAKey
import org.springframework.stereotype.Component
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.util.UUID

/**
 * Get-or-create RSA keypair for RS256, same pattern as
 * iam-identity-svc's PasswordPepperProvider (Service 7) and
 * iam-device-svc's per-tenant TOTP DEK (Service 9): a plain OpenBao KV v2
 * secret, not OpenBao Transit or PKI (no bootstrap tooling for those yet --
 * see docs/DECISIONS.md, Service 11 entry). One platform-wide keypair, not
 * rotated -- BUILD_PLAN.md calls for "rotating JWKS," which needs a
 * multi-key-with-overlap rotation scheme; deferred as MVP-TEMPORARY, logged
 * rather than silently dropped.
 */
@Component
class OidcSigningKeyProvider(
    private val openBaoClient: OpenBaoClient,
) {
    @Volatile
    private var cached: RSAKey? = null

    fun get(): RSAKey {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val key = load() ?: generateAndStore()
            cached = key
            return key
        }
    }

    private fun load(): RSAKey? {
        val secret = openBaoClient.readSecretOrNull(KEY_PATH) ?: return null
        return RSAKey.parse(secret["jwk"] as String)
    }

    private fun generateAndStore(): RSAKey {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val keyPair = keyPairGenerator.generateKeyPair()
        val rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
            .privateKey(keyPair.private as RSAPrivateKey)
            .keyID(UUID.randomUUID().toString())
            .build()
        openBaoClient.writeSecret(KEY_PATH, mapOf("jwk" to rsaKey.toJSONString()))
        return rsaKey
    }

    companion object {
        private const val KEY_PATH = "oidc-signing-key"
    }
}
