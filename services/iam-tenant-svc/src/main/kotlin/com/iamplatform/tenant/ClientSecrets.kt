package com.iamplatform.tenant

import java.security.SecureRandom
import java.util.Base64

/** Same shape as iam-session-svc's SessionTokens -- 256 bits, base64url. */
object ClientSecrets {
    private val random = SecureRandom()

    fun generate(): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}
