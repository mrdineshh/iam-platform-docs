package com.iamplatform.oidc

import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.time.Duration
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class TokenServiceTest {

    private val rsaKey: RSAKey = RSAKeyGenerator(2048).keyID("test-key").generate()
    private val signingKeyProvider = mock<OidcSigningKeyProvider>().also { whenever(it.get()).thenReturn(rsaKey) }
    private val tokenService = TokenService(signingKeyProvider)

    private val issuer = "http://localhost:8090"
    private val clientId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val tenantId = UUID.randomUUID()

    @Test
    fun `issued id token round-trips through verifyAndParse with the right claims`() {
        val idToken = tokenService.issueIdToken(issuer, clientId, userId, tenantId, "carol@acme.com", Duration.ofMinutes(10))

        val claims = tokenService.verifyAndParse(idToken)

        assertEquals(userId.toString(), claims.subject)
        assertEquals(issuer, claims.issuer)
        assertEquals(tenantId.toString(), claims.getStringClaim("tenant_id"))
        assertEquals("carol@acme.com", claims.getStringClaim("email"))
        assertTrue(claims.audience.contains(clientId.toString()))
    }

    @Test
    fun `issued access token carries scope and email`() {
        val accessToken = tokenService.issueAccessToken(issuer, userId, tenantId, "carol@acme.com", "openid profile email", Duration.ofMinutes(10))

        val claims = tokenService.verifyAndParse(accessToken)

        assertEquals(userId.toString(), claims.subject)
        assertEquals("openid profile email", claims.getStringClaim("scope"))
    }

    @Test
    fun `rejects a token signed with a different key`() {
        val otherKey = RSAKeyGenerator(2048).keyID("other-key").generate()
        val otherSigningProvider = mock<OidcSigningKeyProvider>().also { whenever(it.get()).thenReturn(otherKey) }
        val forgedToken = TokenService(otherSigningProvider)
            .issueAccessToken(issuer, userId, tenantId, "carol@acme.com", "openid", Duration.ofMinutes(10))

        assertThrows<InvalidTokenException> {
            tokenService.verifyAndParse(forgedToken)
        }
    }

    @Test
    fun `rejects an expired token`() {
        val expiredToken = tokenService.issueAccessToken(issuer, userId, tenantId, "carol@acme.com", "openid", Duration.ofSeconds(-1))

        assertThrows<InvalidTokenException> {
            tokenService.verifyAndParse(expiredToken)
        }
    }

    @Test
    fun `rejects a malformed token`() {
        assertThrows<InvalidTokenException> {
            tokenService.verifyAndParse("not.a.jwt")
        }
    }

    @Test
    fun `public JWK set exposes the public key without the private key`() {
        val jwkSet = tokenService.publicJwkSet()
        val publicJwk = jwkSet.keys.single()

        assertEquals(rsaKey.keyID, publicJwk.keyID)
        assertTrue(!publicJwk.isPrivate)
    }
}
