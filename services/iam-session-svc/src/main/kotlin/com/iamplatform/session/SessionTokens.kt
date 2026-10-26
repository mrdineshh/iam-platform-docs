package com.iamplatform.session

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import java.util.HexFormat

object SessionTokens {

    private val random = SecureRandom()

    /** 256 bits of CSPRNG output, base64url without padding (43 chars). */
    fun generate(): String {
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    /**
     * Sessions are keyed by SHA-256 of the token, so a dump of the session
     * keyspace alone doesn't yield usable bearer tokens. A plain hash (no
     * salt/stretching) is sufficient here: the input is 256 bits of random
     * data, not a guessable password.
     */
    fun hash(token: String): String =
        HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.toByteArray(StandardCharsets.UTF_8)))
}
