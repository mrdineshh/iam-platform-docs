package com.iamplatform.tenant

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class GoogleWorkspaceLicensePlanTest {

    @Test
    fun `defaults to Business Starter when no sku id is given`() {
        assertEquals(GoogleWorkspaceLicensePlan.BUSINESS_STARTER, GoogleWorkspaceLicensePlan.fromSkuId(null))
    }

    @Test
    fun `defaults to Business Starter for an unrecognized sku id`() {
        assertEquals(GoogleWorkspaceLicensePlan.BUSINESS_STARTER, GoogleWorkspaceLicensePlan.fromSkuId("not-a-real-sku"))
    }

    @Test
    fun `resolves a known sku id to its plan`() {
        assertEquals(GoogleWorkspaceLicensePlan.ENTERPRISE_PLUS, GoogleWorkspaceLicensePlan.fromSkuId("1010020020"))
    }

    @Test
    fun `every plan has a unique sku id`() {
        val skuIds = GoogleWorkspaceLicensePlan.entries.map { it.skuId }
        assertEquals(skuIds.size, skuIds.toSet().size)
    }
}
