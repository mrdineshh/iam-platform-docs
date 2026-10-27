package com.iamplatform.policy

import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.mockito.kotlin.any
import org.mockito.kotlin.eq
import org.mockito.kotlin.mock
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNull

class PolicyServiceTest {

    private val repository = mock<PolicyRepository>()
    private val auditPublisher = mock<AuditPublisher>()
    private val service = PolicyService(repository, auditPublisher)

    private val tenantId = UUID.randomUUID()

    @Test
    fun `getPolicy returns the stored policy at TENANT scope`() {
        val policy = PolicyEntity(id = UUID.randomUUID(), tenantId = tenantId, scope = PolicyScope.TENANT, scopeId = tenantId)
        whenever(repository.findByTenantIdAndScopeAndScopeId(tenantId, PolicyScope.TENANT, tenantId)).thenReturn(policy)

        val result = service.getPolicy(tenantId, PolicyScope.TENANT, scopeId = null)

        assertEquals(tenantId, result.scopeId)
    }

    @Test
    fun `getPolicy throws when nothing is stored yet at that exact scope`() {
        whenever(repository.findByTenantIdAndScopeAndScopeId(tenantId, PolicyScope.TENANT, tenantId)).thenReturn(null)

        assertThrows<PolicyNotFoundException> {
            service.getPolicy(tenantId, PolicyScope.TENANT, scopeId = null)
        }
    }

    @Test
    fun `getPolicy requires scopeId for OU-USER scope`() {
        assertThrows<InvalidPolicyRequestException> {
            service.getPolicy(tenantId, PolicyScope.OU, scopeId = null)
        }
    }

    @Test
    fun `putPolicy at TENANT scope uses tenantId as scopeId and publishes policy-updated`() {
        whenever(repository.findByTenantIdAndScopeAndScopeId(eq(tenantId), eq(PolicyScope.TENANT), eq(tenantId)))
            .thenReturn(null)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.putPolicy(
            PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.TENANT, blockedCountries = listOf("RU")),
        )

        assertEquals(tenantId, result.scopeId)
        assertEquals("RU", result.blockedCountries)
        verify(auditPublisher, times(1)).publish(any<AuditEvent>())
    }

    @Test
    fun `putPolicy at OU scope requires scopeId`() {
        assertThrows<InvalidPolicyRequestException> {
            service.putPolicy(PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.OU, scopeId = null))
        }
    }

    @Test
    fun `putPolicy rejects a hard-cap flag on a non-TENANT scope`() {
        val ouId = UUID.randomUUID()
        assertThrows<InvalidPolicyRequestException> {
            service.putPolicy(
                PutPolicyRequest(
                    tenantId = tenantId,
                    scope = PolicyScope.OU,
                    scopeId = ouId,
                    blockedCountriesHardCap = true,
                ),
            )
        }
    }

    @Test
    fun `putPolicy updates an existing row instead of duplicating it`() {
        val existing = PolicyEntity(id = UUID.randomUUID(), tenantId = tenantId, scope = PolicyScope.TENANT, scopeId = tenantId)
        whenever(repository.findByTenantIdAndScopeAndScopeId(tenantId, PolicyScope.TENANT, tenantId)).thenReturn(existing)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val result = service.putPolicy(
            PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.TENANT, allowedCountries = listOf("US")),
        )

        assertEquals(existing.id, result.id)
        assertEquals("US", result.allowedCountries)
    }

    @Test
    fun `evaluate loads tenant, OU, and user policies by id and delegates to PolicyEvaluator`() {
        val ouId = UUID.randomUUID()
        val userId = UUID.randomUUID()
        val tenantPolicy = PolicyEntity(
            id = UUID.randomUUID(), tenantId = tenantId, scope = PolicyScope.TENANT, scopeId = tenantId,
            blockedCountries = "RU",
        )
        whenever(repository.findByTenantIdAndScopeAndScopeId(tenantId, PolicyScope.TENANT, tenantId)).thenReturn(tenantPolicy)
        whenever(repository.findByTenantIdAndScopeAndScopeId(tenantId, PolicyScope.OU, ouId)).thenReturn(null)
        whenever(repository.findByTenantIdAndScopeAndScopeId(tenantId, PolicyScope.USER, userId)).thenReturn(null)

        val result = service.evaluate(EvaluateRequest(tenantId = tenantId, ouId = ouId, userId = userId, country = "RU"))

        assertEquals(false, result.allowed)
        assertEquals(PolicyScope.TENANT, result.policyScopeApplied)
    }

    @Test
    fun `evaluate with no ouId or userId only looks up the tenant policy`() {
        whenever(repository.findByTenantIdAndScopeAndScopeId(tenantId, PolicyScope.TENANT, tenantId)).thenReturn(null)

        val result = service.evaluate(EvaluateRequest(tenantId = tenantId, country = "US"))

        assertEquals(true, result.allowed)
        assertNull(result.policyScopeApplied)
    }

    @Test
    fun `securitySettings returns platform defaults when no tenant policy is stored`() {
        whenever(repository.findByTenantIdAndScopeAndScopeId(tenantId, PolicyScope.TENANT, tenantId)).thenReturn(null)

        val settings = service.securitySettings(tenantId)

        assertEquals(8, settings.passwordMinLength)
        assertEquals(false, settings.passwordRequireUppercase)
        assertEquals(0, settings.lockoutThreshold)
        assertEquals(15, settings.lockoutDurationMinutes)
        assertEquals(false, settings.lockoutPermanent)
    }

    @Test
    fun `securitySettings returns stored tenant values and defaults for anything unset`() {
        val stored = PolicyEntity(
            id = UUID.randomUUID(), tenantId = tenantId, scope = PolicyScope.TENANT, scopeId = tenantId,
            passwordMinLength = 14, passwordRequireDigit = true, lockoutThreshold = 5, lockoutPermanent = true,
        )
        whenever(repository.findByTenantIdAndScopeAndScopeId(tenantId, PolicyScope.TENANT, tenantId)).thenReturn(stored)

        val settings = service.securitySettings(tenantId)

        assertEquals(14, settings.passwordMinLength)
        assertEquals(true, settings.passwordRequireDigit)
        assertEquals(false, settings.passwordRequireSymbol)
        assertEquals(5, settings.lockoutThreshold)
        assertEquals(15, settings.lockoutDurationMinutes)
        assertEquals(true, settings.lockoutPermanent)
    }

    @Test
    fun `putPolicy stores the password and lockout settings on the tenant policy`() {
        whenever(repository.findByTenantIdAndScopeAndScopeId(eq(tenantId), eq(PolicyScope.TENANT), eq(tenantId))).thenReturn(null)
        whenever(repository.save(any())).thenAnswer { it.arguments[0] }

        val saved = service.putPolicy(
            PutPolicyRequest(
                tenantId = tenantId, scope = PolicyScope.TENANT,
                passwordMinLength = 12, passwordRequireUppercase = true, lockoutThreshold = 5, lockoutDurationMinutes = 30,
            ),
        )

        assertEquals(12, saved.passwordMinLength)
        assertEquals(true, saved.passwordRequireUppercase)
        assertEquals(5, saved.lockoutThreshold)
        assertEquals(30, saved.lockoutDurationMinutes)
    }

    @Test
    fun `password and lockout settings are rejected on OU and USER scope`() {
        assertThrows<InvalidPolicyRequestException> {
            service.putPolicy(PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.OU, scopeId = UUID.randomUUID(), passwordMinLength = 12))
        }
        assertThrows<InvalidPolicyRequestException> {
            service.putPolicy(PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.USER, scopeId = UUID.randomUUID(), lockoutThreshold = 3))
        }
    }

    @Test
    fun `out-of-range password and lockout values are rejected`() {
        for (bad in listOf(
            PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.TENANT, passwordMinLength = 4),
            PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.TENANT, passwordMinLength = 500),
            PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.TENANT, lockoutThreshold = -1),
            PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.TENANT, lockoutThreshold = 101),
            PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.TENANT, lockoutDurationMinutes = 0),
            PutPolicyRequest(tenantId = tenantId, scope = PolicyScope.TENANT, lockoutDurationMinutes = 20000),
        )) {
            assertThrows<InvalidPolicyRequestException> { service.putPolicy(bad) }
        }
    }
}
