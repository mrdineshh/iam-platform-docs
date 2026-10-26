package com.iamplatform.tenant

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.stereotype.Component

/**
 * No pepper here, unlike iam-identity-svc's PasswordService -- a client
 * secret is already 256 bits of our own SecureRandom output (ClientSecrets),
 * not a human-chosen low-entropy password, so peppering adds no real
 * resistance and isn't worth another OpenBao round-trip for this case.
 */
@Component
class ClientSecretHasher {
    private val encoder = Argon2PasswordEncoder(16, 32, 1, 19456, 2)

    fun hash(secret: String): String = encoder.encode(secret)!!

    fun matches(secret: String, hash: String): Boolean = encoder.matches(secret, hash)
}
