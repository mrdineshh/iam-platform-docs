package com.iamplatform.tenant

import jakarta.validation.Validation
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Spec 13.2: privileged Endpoint Security actions must carry a reason. Checked at the request boundary with Bean Validation. */
class DeviceActionReasonTest {

    private val validator = Validation.buildDefaultValidatorFactory().validator

    @Test
    fun `a device action with no reason, a blank one or one over 500 characters is invalid`() {
        for (reason in listOf(null, "", "   ", "x".repeat(501))) {
            assertTrue(validator.validate(DeviceActionRequest(reason)).isNotEmpty(), "reason=${reason?.take(10)}")
        }
    }

    @Test
    fun `a device action with a reason is valid`() {
        assertEquals(0, validator.validate(DeviceActionRequest("Laptop reported lost")).size)
    }

    @Test
    fun `switching a tenant-wide control without a reason is invalid`() {
        assertTrue(validator.validate(DeviceLoginRuleRequest(true, null)).isNotEmpty())
        assertTrue(validator.validate(BrowserControlsRequest(true, " ")).isNotEmpty())
        assertEquals(0, validator.validate(DeviceLoginRuleRequest(false, "Demo finished")).size)
        assertEquals(0, validator.validate(BrowserControlsRequest(true, "Policy from HR")).size)
    }
}
