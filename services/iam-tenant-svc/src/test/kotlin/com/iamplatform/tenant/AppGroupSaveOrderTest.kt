package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.inOrder
import org.mockito.kotlin.mock
import org.mockito.kotlin.whenever
import java.util.UUID

/**
 * Regression: saving an app's group access used to fail with a unique-index violation (HTTP 500, "temporarily unavailable"
 * in the console) whenever the new selection kept a group that was already assigned, because Hibernate runs INSERTs before
 * DELETEs at flush. The delete must reach the database BEFORE the new rows are inserted.
 */
class AppGroupSaveOrderTest {

    private val keptGroup = UUID.randomUUID()
    private val newGroup = UUID.randomUUID()

    @Test
    fun `OIDC app - the delete is flushed before the replacement rows are saved`() {
        val repository = mock<OidcClientRepository>()
        val groups = mock<OidcClientGroupRepository>()
        val service = OidcClientService(repository, mock<TenantRepository>(), groups, mock<ClientSecretHasher>(), mock<AuditPublisher>())
        val clientId = UUID.randomUUID()
        whenever(repository.existsById(clientId)).thenReturn(true)

        service.setGroups(clientId, listOf(keptGroup, newGroup, keptGroup))

        val order = inOrder(groups)
        order.verify(groups).deleteByOidcClientId(clientId)
        order.verify(groups).flush()
        order.verify(groups).saveAll(any<List<OidcClientGroupEntity>>())
    }

    @Test
    fun `SAML app - the delete is flushed before the replacement rows are saved`() {
        val repository = mock<SamlSpRepository>()
        val groups = mock<SamlSpGroupRepository>()
        val service = SamlSpService(repository, mock<TenantRepository>(), groups, mock<AuditPublisher>())
        val spId = UUID.randomUUID()
        whenever(repository.existsById(spId)).thenReturn(true)

        service.setGroups(spId, listOf(keptGroup, newGroup))

        val order = inOrder(groups)
        order.verify(groups).deleteBySamlSpId(spId)
        order.verify(groups).flush()
        order.verify(groups).saveAll(any<List<SamlSpGroupEntity>>())
    }
}
