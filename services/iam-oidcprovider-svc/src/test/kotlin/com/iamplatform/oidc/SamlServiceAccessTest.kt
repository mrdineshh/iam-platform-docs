package com.iamplatform.oidc

import com.iamplatform.oidc.client.IdentityClient
import com.iamplatform.oidc.client.RemoteAppAccess
import com.iamplatform.oidc.client.RemoteSession
import com.iamplatform.oidc.client.RemoteUser
import com.iamplatform.oidc.client.SessionClient
import com.iamplatform.oidc.client.TenantClient
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals

/** Group enforcement on the SAML path: no assertion is signed for a user who may not use the SP. */
class SamlServiceAccessTest {

    private val tenantClient = mock<TenantClient>()
    private val sessionClient = mock<SessionClient>()
    private val identityClient = mock<IdentityClient>()
    private val requestStore = mock<SamlRequestStore>()
    private val signingKeyProvider = mock<SamlSigningKeyProvider>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = SamlService(
        tenantClient, sessionClient, identityClient, requestStore, signingKeyProvider, auditPublisher,
        OidcProperties(issuer = "http://localhost:8090"), SamlProperties(),
    )

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val spId = UUID.randomUUID()
    private val pending = PendingSamlRequest(spId, tenantId, "google.com/a/demo", "https://google.com/acs", "req-1", null)

    private fun givenSignedInUser() {
        whenever(requestStore.consume("req")).thenReturn(pending)
        whenever(sessionClient.find("tok")).thenReturn(RemoteSession(UUID.randomUUID(), tenantId, userId, Instant.now().plusSeconds(3600)))
        whenever(identityClient.findUser(userId)).thenReturn(RemoteUser(userId, tenantId, "ada@demo.econz.net", "Ada", "ACTIVE", Instant.now()))
    }

    @Test
    fun `a user whose group has no access to the SP gets no assertion, and it is audited`() {
        givenSignedInUser()
        whenever(tenantClient.checkAppAccess("saml", spId, "tok")).thenReturn(RemoteAppAccess(false, "you are not in a group that has access to this app"))

        val ex = assertThrows<AppAccessDeniedException> { service.completeSamlAuthorization("tok", "req") }

        assertEquals("you are not in a group that has access to this app", ex.message)
        verify(signingKeyProvider, never()).get()
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("saml.access_denied", captor.firstValue.action)
        assertEquals(userId.toString(), captor.firstValue.actorId)
    }

    @Test
    fun `the check names the SP's id and the caller's own session`() {
        givenSignedInUser()
        whenever(tenantClient.checkAppAccess("saml", spId, "tok")).thenReturn(RemoteAppAccess(false))

        assertThrows<AppAccessDeniedException> { service.completeSamlAuthorization("tok", "req") }

        verify(tenantClient).checkAppAccess("saml", spId, "tok")
    }
}
