package com.iamplatform.session

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class SessionTokensTest {

    @Test
    fun `generated tokens are 43-char base64url and unique`() {
        val tokens = (1..1000).map { SessionTokens.generate() }
        assertEquals(1000, tokens.toSet().size)
        tokens.forEach {
            assertEquals(43, it.length)
            assert(it.matches(Regex("^[A-Za-z0-9_-]+$"))) { "not base64url: $it" }
        }
    }

    @Test
    fun `hash is deterministic and never equals the token`() {
        val token = SessionTokens.generate()
        assertEquals(SessionTokens.hash(token), SessionTokens.hash(token))
        assertNotEquals(token, SessionTokens.hash(token))
        assertEquals(64, SessionTokens.hash(token).length)
    }
}
