package com.iamplatform.oidc

import com.iamplatform.oidc.client.IdentityClient
import com.iamplatform.oidc.client.RemoteOidcClient
import com.iamplatform.oidc.client.RemoteSession
import com.iamplatform.oidc.client.RemoteTenant
import com.iamplatform.oidc.client.RemoteUser
import com.iamplatform.oidc.client.SessionClient
import com.iamplatform.oidc.client.TenantClient
import com.iamplatform.oidc.client.VerifyClientSecretResponse
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.time.Duration
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class OidcServiceTest {

    private val tenantClient = mock<TenantClient>()
    private val sessionClient = mock<SessionClient>()
    private val identityClient = mock<IdentityClient>()
    private val codeStore = mock<AuthorizationCodeStore>()
    private val linkStore = mock<AccessTokenLinkStore>()
    private val tokenService = mock<TokenService>()
    private val auditPublisher = mock<AuditPublisher>()
    private val properties = OidcProperties(issuer = "http://localhost:8090", accessTokenTtl = Duration.ofMinutes(10), idTokenTtl = Duration.ofMinutes(10))

    private val service = OidcService(tenantClient, sessionClient, identityClient, codeStore, linkStore, tokenService, auditPublisher, properties)

    private val clientId = UUID.randomUUID()
    private val tenantId = UUID.randomUUID()
    private val redirectUri = "https://grafana.example.com/callback"

    private fun remoteClient() = RemoteOidcClient(clientId, tenantId, "Grafana", listOf(redirectUri), Instant.now())
    private fun remoteTenant(subdomain: String = "acme") = RemoteTenant(tenantId, "Acme Inc", subdomain, "ACTIVE", Instant.now())

    @Test
    fun `validateAuthorizationRequest rejects an unsupported response_type`() {
        assertThrows<InvalidAuthorizeRequestException> {
            service.validateAuthorizationRequest(clientId, redirectUri, "token")
        }
    }

    @Test
    fun `validateAuthorizationRequest rejects an unknown client_id`() {
        whenever(tenantClient.findClient(clientId)).thenReturn(null)

        assertThrows<InvalidAuthorizeRequestException> {
            service.validateAuthorizationRequest(clientId, redirectUri, "code")
        }
    }

    @Test
    fun `validateAuthorizationRequest rejects a redirect_uri not registered for the client`() {
        whenever(tenantClient.findClient(clientId)).thenReturn(remoteClient())

        assertThrows<InvalidAuthorizeRequestException> {
            service.validateAuthorizationRequest(clientId, "https://evil.example.com/callback", "code")
        }
    }

    @Test
    fun `validateAuthorizationRequest returns the client for a valid request`() {
        whenever(tenantClient.findClient(clientId)).thenReturn(remoteClient())

        val result = service.validateAuthorizationRequest(clientId, redirectUri, "code")

        assertEquals(clientId, result.clientId)
    }

    @Test
    fun `buildLoginRedirect appends the tenant subdomain as a query param in local-dev mode`() {
        whenever(tenantClient.findClient(clientId)).thenReturn(remoteClient())
        whenever(tenantClient.findTenant(tenantId)).thenReturn(remoteTenant("acme"))

        val redirect = service.buildLoginRedirect(clientId, redirectUri, "openid", "xyz")

        assertTrue(redirect.startsWith("http://localhost:3001/login?"))
        assertTrue(redirect.contains("tenant=acme"))
        assertTrue(redirect.contains("client_id=$clientId"))
    }

    @Test
    fun `buildLoginRedirect substitutes a real subdomain host when configured`() {
        val subdomainProperties = properties.copy(loginPortalBaseUrl = "https://{subdomain}.login.platform.com")
        val subdomainService = OidcService(tenantClient, sessionClient, identityClient, codeStore, linkStore, tokenService, auditPublisher, subdomainProperties)
        whenever(tenantClient.findClient(clientId)).thenReturn(remoteClient())
        whenever(tenantClient.findTenant(tenantId)).thenReturn(remoteTenant("acme"))

        val redirect = subdomainService.buildLoginRedirect(clientId, redirectUri, "openid", "xyz")

        assertTrue(redirect.startsWith("https://acme.login.platform.com/login?"))
        assertTrue(!redirect.contains("tenant="))
    }

    @Test
    fun `buildLoginRedirect rejects an unknown client_id without ever calling tenant lookup`() {
        whenever(tenantClient.findClient(clientId)).thenReturn(null)

        assertThrows<InvalidAuthorizeRequestException> {
            service.buildLoginRedirect(clientId, redirectUri, "openid", "xyz")
        }
    }

    @Test
    fun `completeAuthorization issues a code carrying the session's userId and the identity-svc email`() {
        val userId = UUID.randomUUID()
        whenever(tenantClient.findClient(clientId)).thenReturn(remoteClient())
        whenever(sessionClient.find("session-token")).thenReturn(RemoteSession(UUID.randomUUID(), tenantId, userId, Instant.now().plusSeconds(3600)))
        whenever(identityClient.findUser(userId)).thenReturn(RemoteUser(userId, tenantId, "carol@acme.com", "Carol", "ACTIVE", Instant.now()))
        whenever(codeStore.issue(any())).thenReturn("issued-code")

        val redirect = service.completeAuthorization("session-token", clientId, redirectUri, "openid", "xyz")

        assertTrue(redirect.startsWith(redirectUri))
        assertTrue(redirect.contains("code=issued-code"))
        assertTrue(redirect.contains("state=xyz"))
    }

    @Test
    fun `completeAuthorization rejects an unknown or expired session token`() {
        whenever(tenantClient.findClient(clientId)).thenReturn(remoteClient())
        whenever(sessionClient.find("bad-token")).thenReturn(null)

        assertThrows<SessionInvalidException> {
            service.completeAuthorization("bad-token", clientId, redirectUri, "openid", "xyz")
        }
    }

    @Test
    fun `completeAuthorization rejects a session belonging to a different tenant`() {
        whenever(tenantClient.findClient(clientId)).thenReturn(remoteClient())
        whenever(sessionClient.find("session-token")).thenReturn(RemoteSession(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(), Instant.now().plusSeconds(3600)))

        assertThrows<SessionInvalidException> {
            service.completeAuthorization("session-token", clientId, redirectUri, "openid", "xyz")
        }
    }

    @Test
    fun `completeAuthorization rejects an invalid client_id as a JSON error, not the HTML error page`() {
        whenever(tenantClient.findClient(clientId)).thenReturn(null)

        assertThrows<AuthorizeCompleteException> {
            service.completeAuthorization("session-token", clientId, redirectUri, "openid", "xyz")
        }
    }

    @Test
    fun `exchangeToken rejects a code issued to a different redirect_uri`() {
        val data = AuthorizationCodeData(clientId, tenantId, UUID.randomUUID(), "carol@acme.com", redirectUri, "openid", "session-token")
        whenever(codeStore.redeem("code")).thenReturn(data)

        assertThrows<InvalidGrantException> {
            service.exchangeToken("authorization_code", "code", "https://different.example.com/callback", clientId, "secret")
        }
    }

    @Test
    fun `exchangeToken rejects an invalid client secret without issuing tokens`() {
        val data = AuthorizationCodeData(clientId, tenantId, UUID.randomUUID(), "carol@acme.com", redirectUri, "openid", "session-token")
        whenever(codeStore.redeem("code")).thenReturn(data)
        whenever(tenantClient.verifySecret(clientId, "wrong-secret")).thenReturn(VerifyClientSecretResponse(valid = false))

        assertThrows<InvalidClientException> {
            service.exchangeToken("authorization_code", "code", redirectUri, clientId, "wrong-secret")
        }
    }

    @Test
    fun `exchangeToken succeeds and links the access token to the session for later liveness checks`() {
        val userId = UUID.randomUUID()
        val data = AuthorizationCodeData(clientId, tenantId, userId, "carol@acme.com", redirectUri, "openid", "session-token")
        whenever(codeStore.redeem("code")).thenReturn(data)
        whenever(tenantClient.verifySecret(clientId, "secret")).thenReturn(VerifyClientSecretResponse(valid = true, tenantId = tenantId))
        whenever(tokenService.issueIdToken(any(), any(), any(), any(), any(), any())).thenReturn("id-token")
        whenever(tokenService.issueAccessToken(any(), any(), any(), any(), any(), any())).thenReturn("access-token")

        val result = service.exchangeToken("authorization_code", "code", redirectUri, clientId, "secret")

        assertEquals("id-token", result.idToken)
        assertEquals("access-token", result.accessToken)
        assertNotNull(result.expiresIn)
    }
}
