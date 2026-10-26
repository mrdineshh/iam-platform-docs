package com.iamplatform.oidc

import org.springframework.data.redis.core.StringRedisTemplate
import org.springframework.stereotype.Component
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.time.Duration
import java.util.HexFormat

/**
 * Maps an issued access token to the platform session token it was issued
 * for, so /userinfo can re-check session liveness (see SessionClient) on
 * every call without embedding the raw platform session token inside a JWT
 * that's handed to a third-party app -- that would let the third-party
 * app impersonate the user's session directly against every other service,
 * not just read /userinfo. Keyed by a hash of the access token, same
 * reasoning as iam-session-svc never using a raw token as a Valkey key.
 */
@Component
class AccessTokenLinkStore(
    private val redis: StringRedisTemplate,
) {
    fun link(accessToken: String, sessionToken: String, ttl: Duration) {
        redis.opsForValue().set(key(accessToken), sessionToken, ttl)
    }

    fun sessionTokenFor(accessToken: String): String? = redis.opsForValue().get(key(accessToken))

    private fun key(accessToken: String): String {
        val hash = MessageDigest.getInstance("SHA-256").digest(accessToken.toByteArray(StandardCharsets.UTF_8))
        return "oidc:access:${HexFormat.of().formatHex(hash)}"
    }
}
