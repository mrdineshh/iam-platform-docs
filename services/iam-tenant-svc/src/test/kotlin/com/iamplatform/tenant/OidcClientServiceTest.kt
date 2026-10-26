package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OidcClientServiceTest {

    private val repository = mock<OidcClientRepository>()
    private val tenantRepository = mock<TenantRepository>()
    private val secretHasher = mock<ClientSecretHasher>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = OidcClientService(repository, tenantRepository, secretHasher, auditPublisher)

    private val tenantId = UUID.randomUUID()

    @Test
    fun `createClient rejects a nonexistent tenant without generating a secret`() {
        whenever(tenantRepository.existsById(tenantId)).thenReturn(false)

        assertThrows<TenantNotFoundException> {
            service.createClient(CreateOidcClientRequest(tenantId, "Grafana", listOf("https://grafana.example.com/callback")))
        }

        verify(repository, never()).save(any())
    }

    @Test
    fun `createClient stores only the hash and returns the plaintext secret once`() {
        whenever(tenantRepository.existsById(tenantId)).thenReturn(true)
        whenever(secretHasher.hash(any())).thenReturn("hashed-value")
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val (client, secret) = service.createClient(
            CreateOidcClientRequest(tenantId, "Grafana", listOf("https://grafana.example.com/callback")),
        )

        assertEquals("hashed-value", client.clientSecretHash)
        assertTrue(secret.isNotBlank())
        assertTrue(secret != client.clientSecretHash)
        verify(auditPublisher, times(1)).publish(any<AuditEvent>())
    }

    @Test
    fun `verifySecret returns valid with tenantId on a correct secret`() {
        val id = UUID.randomUUID()
        val client = OidcClientEntity(id, tenantId, "Grafana", "stored-hash", "https://grafana.example.com/callback")
        whenever(repository.findById(id)).thenReturn(Optional.of(client))
        whenever(secretHasher.matches("correct", "stored-hash")).thenReturn(true)

        val result = service.verifySecret(id, VerifyClientSecretRequest("correct"))

        assertEquals(true, result.valid)
        assertEquals(tenantId, result.tenantId)
    }

    @Test
    fun `verifySecret returns the same invalid shape for an unknown client as for a wrong secret`() {
        val unknownId = UUID.randomUUID()
        whenever(repository.findById(unknownId)).thenReturn(Optional.empty())

        val result = service.verifySecret(unknownId, VerifyClientSecretRequest("anything"))

        assertEquals(false, result.valid)
        assertNull(result.tenantId)
    }

    @Test
    fun `listClients returns only this tenant's clients`() {
        val client = OidcClientEntity(UUID.randomUUID(), tenantId, "Grafana", "hash", "https://grafana.example.com/callback")
        whenever(repository.findByTenantId(tenantId)).thenReturn(listOf(client))

        val result = service.listClients(tenantId)

        assertEquals(1, result.size)
        assertEquals("Grafana", result[0].name)
    }
}
