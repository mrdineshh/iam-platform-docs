package com.iamplatform.policy

import org.junit.jupiter.api.Test
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PolicyEvaluatorTest {

    private fun policy(
        scope: PolicyScope,
        allowed: List<String>? = null,
        allowedHardCap: Boolean = false,
        blocked: List<String>? = null,
        blockedHardCap: Boolean = false,
    ): PolicyEntity {
        val id = UUID.randomUUID()
        return PolicyEntity(
            id = id,
            tenantId = UUID.randomUUID(),
            scope = scope,
            scopeId = id,
            allowedCountries = allowed.toCsv(),
            allowedCountriesHardCap = allowedHardCap,
            blockedCountries = blocked.toCsv(),
            blockedCountriesHardCap = blockedHardCap,
        )
    }

    @Test
    fun `no policies at all means allowed with no scope attributed`() {
        val result = PolicyEvaluator.evaluate(null, null, null, "US")
        assertTrue(result.allowed)
        assertNull(result.reason)
        assertNull(result.policyScopeApplied)
    }

    @Test
    fun `tenant block-list denies a listed country`() {
        val tenant = policy(PolicyScope.TENANT, blocked = listOf("RU", "KP"))
        val result = PolicyEvaluator.evaluate(tenant, null, null, "RU")
        assertFalse(result.allowed)
        assertEquals(PolicyScope.TENANT, result.policyScopeApplied)
    }

    @Test
    fun `tenant block-list allows an unlisted country`() {
        val tenant = policy(PolicyScope.TENANT, blocked = listOf("RU", "KP"))
        val result = PolicyEvaluator.evaluate(tenant, null, null, "US")
        assertTrue(result.allowed)
    }

    @Test
    fun `tenant allow-list denies a country not on the list`() {
        val tenant = policy(PolicyScope.TENANT, allowed = listOf("US", "CA"))
        val result = PolicyEvaluator.evaluate(tenant, null, null, "FR")
        assertFalse(result.allowed)
        assertEquals(PolicyScope.TENANT, result.policyScopeApplied)
    }

    @Test
    fun `tenant allow-list allows a listed country`() {
        val tenant = policy(PolicyScope.TENANT, allowed = listOf("US", "CA"))
        val result = PolicyEvaluator.evaluate(tenant, null, null, "US")
        assertTrue(result.allowed)
    }

    @Test
    fun `OU block-list overrides tenant block-list when not hard-capped`() {
        val tenant = policy(PolicyScope.TENANT, blocked = listOf("RU"))
        val ou = policy(PolicyScope.OU, blocked = listOf("FR"))
        // RU is only in the tenant's list, which OU's own definition overrides entirely.
        val resultRu = PolicyEvaluator.evaluate(tenant, ou, null, "RU")
        assertTrue(resultRu.allowed)

        val resultFr = PolicyEvaluator.evaluate(tenant, ou, null, "FR")
        assertFalse(resultFr.allowed)
        assertEquals(PolicyScope.OU, resultFr.policyScopeApplied)
    }

    @Test
    fun `OU inherits tenant block-list when OU does not define the attribute`() {
        val tenant = policy(PolicyScope.TENANT, blocked = listOf("RU"))
        val ou = policy(PolicyScope.OU) // defines nothing
        val result = PolicyEvaluator.evaluate(tenant, ou, null, "RU")
        assertFalse(result.allowed)
        assertEquals(PolicyScope.TENANT, result.policyScopeApplied)
    }

    @Test
    fun `user block-list overrides OU block-list which overrides tenant`() {
        val tenant = policy(PolicyScope.TENANT, blocked = listOf("RU"))
        val ou = policy(PolicyScope.OU, blocked = listOf("FR"))
        val user = policy(PolicyScope.USER, blocked = listOf("DE"))

        assertTrue(PolicyEvaluator.evaluate(tenant, ou, user, "RU").allowed)
        assertTrue(PolicyEvaluator.evaluate(tenant, ou, user, "FR").allowed)
        val result = PolicyEvaluator.evaluate(tenant, ou, user, "DE")
        assertFalse(result.allowed)
        assertEquals(PolicyScope.USER, result.policyScopeApplied)
    }

    @Test
    fun `tenant hard-cap on block-list cannot be overridden by OU`() {
        val tenant = policy(PolicyScope.TENANT, blocked = listOf("KP"), blockedHardCap = true)
        val ou = policy(PolicyScope.OU, blocked = listOf("US"))

        // OU's attempt to block US is ignored entirely -- the hard-capped
        // tenant value replaces it, it does not merge with it.
        val resultUs = PolicyEvaluator.evaluate(tenant, ou, null, "US")
        assertTrue(resultUs.allowed)

        val resultKp = PolicyEvaluator.evaluate(tenant, ou, null, "KP")
        assertFalse(resultKp.allowed)
        assertEquals(PolicyScope.TENANT, resultKp.policyScopeApplied)
    }

    @Test
    fun `tenant hard-cap on block-list cannot be overridden by user even through OU`() {
        val tenant = policy(PolicyScope.TENANT, blocked = listOf("KP"), blockedHardCap = true)
        val ou = policy(PolicyScope.OU, blocked = listOf("US"))
        val user = policy(PolicyScope.USER, blocked = listOf("FR"))

        val result = PolicyEvaluator.evaluate(tenant, ou, user, "FR")
        assertTrue(result.allowed)
    }

    @Test
    fun `tenant hard-cap on allow-list cannot be widened by user`() {
        val tenant = policy(PolicyScope.TENANT, allowed = listOf("US"), allowedHardCap = true)
        val user = policy(PolicyScope.USER, allowed = listOf("US", "FR"))

        val result = PolicyEvaluator.evaluate(tenant, null, user, "FR")
        assertFalse(result.allowed)
        assertEquals(PolicyScope.TENANT, result.policyScopeApplied)
    }

    @Test
    fun `block-list takes precedence over allow-list for the same country`() {
        val tenant = policy(PolicyScope.TENANT, allowed = listOf("US"), blocked = listOf("US"))
        val result = PolicyEvaluator.evaluate(tenant, null, null, "US")
        assertFalse(result.allowed)
        assertEquals("country 'US' is in blockedCountries", result.reason)
    }

    @Test
    fun `non-hard-capped tenant allow-list is still overridable by a defined OU allow-list`() {
        val tenant = policy(PolicyScope.TENANT, allowed = listOf("US"))
        val ou = policy(PolicyScope.OU, allowed = listOf("FR"))
        val result = PolicyEvaluator.evaluate(tenant, ou, null, "FR")
        assertTrue(result.allowed)
    }
}
