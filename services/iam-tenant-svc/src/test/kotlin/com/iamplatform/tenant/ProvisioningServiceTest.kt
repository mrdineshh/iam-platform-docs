package com.iamplatform.tenant

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.vault.OpenBaoClient
import org.junit.jupiter.api.Test
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doAnswer
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.Optional
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProvisioningServiceTest {

    private val connections = mock<ScimConnectionRepository>()
    private val accounts = mock<ProvisionedAccountRepository>()
    private val scim = mock<ScimClient>()
    private val openBao = mock<OpenBaoClient>()
    private val oidcClients = mock<OidcClientRepository>()
    private val samlSps = mock<SamlSpRepository>()
    private val identityClient = mock<IdentityClient>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = ProvisioningService(connections, accounts, scim, openBao, oidcClients, samlSps, identityClient, auditPublisher)

    private val tenantId = UUID.randomUUID()
    private val userId = UUID.randomUUID()
    private val pulseApp = UUID.randomUUID()
    private val pulse = ScimConnectionEntity(UUID.randomUUID(), tenantId, "OIDC", pulseApp, "https://pulse.example.com/scim/v2")

    // A tiny in-memory stand-in for the provisioned_accounts table.
    private val store = mutableMapOf<Pair<UUID, UUID>, ProvisionedAccountEntity>()

    init {
        whenever(accounts.findByUserIdAndConnectionId(any(), any())).thenAnswer { store[it.getArgument<UUID>(0) to it.getArgument<UUID>(1)] }
        whenever(accounts.findByUserId(any())).thenAnswer { inv -> store.values.filter { it.userId == inv.getArgument<UUID>(0) } }
        whenever(accounts.save(any<ProvisionedAccountEntity>())).thenAnswer {
            val a = it.getArgument<ProvisionedAccountEntity>(0)
            store[a.userId to a.connectionId] = a
            a
        }
        doAnswer { val a = it.getArgument<ProvisionedAccountEntity>(0); store.remove(a.userId to a.connectionId); null }
            .whenever(accounts).delete(any<ProvisionedAccountEntity>())

        whenever(connections.findByTenantIdAndEnabledTrue(tenantId)).thenReturn(listOf(pulse))
        whenever(connections.findById(pulse.id)).thenReturn(Optional.of(pulse))
        whenever(oidcClients.findById(pulseApp)).thenReturn(Optional.of(OidcClientEntity(pulseApp, tenantId, "Pulse", "h", "https://p/cb")))
        whenever(openBao.readSecretOrNull("scim/${pulse.id}")).thenReturn(mapOf("token" to "tok"))
    }

    private fun user(active: Boolean = true) = ProvisionUser(userId, tenantId, "ada@econz.net", "Ada Lovelace", active)

    private fun existingAccount(state: AccountState, externalId: String? = "app-1", error: String? = null) =
        ProvisionedAccountEntity(UUID.randomUUID(), tenantId, userId, pulse.id, externalId, state.name, error)
            .also { store[userId to pulse.id] = it }

    @Test
    fun `a new user is created in the app and the app's id is remembered`() {
        whenever(scim.createUser(eq(pulse.baseUrl), eq("tok"), any())).thenReturn("app-1")

        val results = service.reconcile(user())

        assertEquals(listOf(TargetResult("Pulse", "created", ok = true)), results)
        val account = store.getValue(userId to pulse.id)
        assertEquals("app-1", account.externalId)
        assertEquals(AccountState.ACTIVE.name, account.state)
        assertNull(account.lastError)
    }

    @Test
    fun `the SCIM request carries the user's email, platform id and split name`() {
        whenever(scim.createUser(any(), any(), any())).thenReturn("app-1")

        service.reconcile(user())

        val captor = argumentCaptor<ScimUserSpec>()
        verify(scim).createUser(any(), any(), captor.capture())
        assertEquals("ada@econz.net", captor.firstValue.userName)
        assertEquals(userId.toString(), captor.firstValue.externalId)
        assertEquals("Ada", captor.firstValue.givenName)
        assertEquals("Lovelace", captor.firstValue.familyName)
        assertTrue(captor.firstValue.active)
    }

    @Test
    fun `a suspended user the app never had is skipped, not created`() {
        val results = service.reconcile(user(active = false))

        assertEquals("skipped", results.single().action)
        verify(scim, never()).createUser(any(), any(), any())
        assertTrue(store.isEmpty())
    }

    @Test
    fun `suspending an active user suspends their app account`() {
        existingAccount(AccountState.ACTIVE)

        val results = service.reconcile(user(active = false))

        assertEquals("suspended", results.single().action)
        verify(scim).setActive(pulse.baseUrl, "tok", "app-1", false)
        assertEquals(AccountState.SUSPENDED.name, store.getValue(userId to pulse.id).state)
    }

    @Test
    fun `reactivating a suspended user reactivates their app account`() {
        existingAccount(AccountState.SUSPENDED)

        val results = service.reconcile(user(active = true))

        assertEquals("reactivated", results.single().action)
        verify(scim).setActive(pulse.baseUrl, "tok", "app-1", true)
        assertEquals(AccountState.ACTIVE.name, store.getValue(userId to pulse.id).state)
    }

    @Test
    fun `when the app already matches nothing is sent`() {
        existingAccount(AccountState.ACTIVE)

        val results = service.reconcile(user(active = true))

        assertEquals("unchanged", results.single().action)
        verify(scim, never()).setActive(any(), any(), any(), any())
        verify(scim, never()).createUser(any(), any(), any())
        verify(auditPublisher, never()).publish(any())
    }

    @Test
    fun `an app that already has the user (409) is linked and made active`() {
        whenever(scim.createUser(any(), any(), any())).thenThrow(ScimException("exists", 409))
        whenever(scim.findIdByUserName(pulse.baseUrl, "tok", "ada@econz.net")).thenReturn("pre-existing")

        val results = service.reconcile(user())

        assertEquals("linked", results.single().action)
        verify(scim).setActive(pulse.baseUrl, "tok", "pre-existing", true)
        assertEquals("pre-existing", store.getValue(userId to pulse.id).externalId)
    }

    @Test
    fun `a failing app is reported and recorded but never throws, and the error is cleared by a later success`() {
        whenever(scim.createUser(any(), any(), any())).thenThrow(ScimException("The app answered HTTP 500"))

        val failed = service.reconcile(user()).single()

        assertFalse(failed.ok)
        assertEquals("failed", failed.action)
        assertEquals("The app answered HTTP 500", failed.error)
        val row = store.getValue(userId to pulse.id)
        assertEquals("The app answered HTTP 500", row.lastError)
        assertEquals(AccountState.PENDING.name, row.state)
        val captor = argumentCaptor<AuditEvent>()
        verify(auditPublisher).publish(captor.capture())
        assertEquals("provisioning.failed", captor.firstValue.action)
        assertEquals(AuditResult.FAILURE, captor.firstValue.result)

        // Retry once the app is back.
        whenever(scim.createUser(any(), any(), any())).thenReturn("app-1")
        val retried = service.reconcile(user()).single()
        assertTrue(retried.ok)
        assertNull(store.getValue(userId to pulse.id).lastError)
        assertEquals(AccountState.ACTIVE.name, store.getValue(userId to pulse.id).state)
    }

    @Test
    fun `a missing token is a clear failure, not a crash`() {
        whenever(openBao.readSecretOrNull("scim/${pulse.id}")).thenReturn(null)

        val result = service.reconcile(user()).single()

        assertFalse(result.ok)
        assertTrue(result.error!!.contains("No access token"))
        verify(scim, never()).createUser(any(), any(), any())
    }

    @Test
    fun `one failing app does not stop the others`() {
        val jiraApp = UUID.randomUUID()
        val jira = ScimConnectionEntity(UUID.randomUUID(), tenantId, "SAML", jiraApp, "https://jira.example.com/scim/v2")
        whenever(connections.findByTenantIdAndEnabledTrue(tenantId)).thenReturn(listOf(pulse, jira))
        whenever(samlSps.findById(jiraApp)).thenReturn(Optional.of(SamlSpEntity(jiraApp, tenantId, "Jira", "e", "https://j/acs")))
        whenever(openBao.readSecretOrNull("scim/${jira.id}")).thenReturn(mapOf("token" to "jira-tok"))
        whenever(scim.createUser(eq(pulse.baseUrl), any(), any())).thenThrow(ScimException("down"))
        whenever(scim.createUser(eq(jira.baseUrl), any(), any())).thenReturn("jira-1")

        val results = service.reconcile(user())

        assertEquals(listOf("Pulse" to false, "Jira" to true), results.map { it.target to it.ok })
    }

    @Test
    fun `disabled connections are not provisioned to`() {
        whenever(connections.findByTenantIdAndEnabledTrue(tenantId)).thenReturn(emptyList())

        assertTrue(service.reconcile(user()).isEmpty())
        verify(scim, never()).createUser(any(), any(), any())
    }

    @Test
    fun `deleting a user deletes only the accounts we created, and forgets them`() {
        existingAccount(AccountState.ACTIVE, externalId = "app-1")

        val results = service.deprovision(tenantId, userId, "ada@econz.net")

        assertEquals("deleted", results.single().action)
        verify(scim).deleteUser(pulse.baseUrl, "tok", "app-1")
        assertTrue(store.isEmpty())
    }

    @Test
    fun `a failed delete keeps the record so it can be retried`() {
        existingAccount(AccountState.ACTIVE, externalId = "app-1")
        whenever(scim.deleteUser(any(), any(), any())).thenThrow(ScimException("The app answered HTTP 503"))

        val results = service.deprovision(tenantId, userId, "ada@econz.net")

        assertFalse(results.single().ok)
        assertNotNull(store[userId to pulse.id])
        assertEquals("The app answered HTTP 503", store.getValue(userId to pulse.id).lastError)
    }

    @Test
    fun `an account that was never created in the app is just forgotten`() {
        existingAccount(AccountState.PENDING, externalId = null, error = "earlier failure")

        val results = service.deprovision(tenantId, userId, "ada@econz.net")

        assertEquals("skipped", results.single().action)
        verify(scim, never()).deleteUser(any(), any(), any())
        assertTrue(store.isEmpty())
    }

    @Test
    fun `syncing a connection brings every user in the tenant in line and counts the outcome`() {
        val other = UUID.randomUUID()
        whenever(identityClient.listUsers(tenantId)).thenReturn(
            listOf(
                RemoteUserListEntry(userId, tenantId, "ada@econz.net", "Ada Lovelace", RemoteUserStatus.ACTIVE, RemoteUserRole.USER),
                RemoteUserListEntry(other, tenantId, "bob@econz.net", "Bob Builder", RemoteUserStatus.ACTIVE, RemoteUserRole.USER),
            ),
        )
        whenever(scim.createUser(any(), any(), argThatEmail("ada@econz.net"))).thenReturn("a-1")
        whenever(scim.createUser(any(), any(), argThatEmail("bob@econz.net"))).thenThrow(ScimException("nope"))

        val summary = service.syncConnection(pulse)

        assertEquals(SyncSummary(users = 2, succeeded = 1, failed = 1), summary)
    }

    private fun argThatEmail(email: String): ScimUserSpec = org.mockito.kotlin.argThat { userName == email }
}
