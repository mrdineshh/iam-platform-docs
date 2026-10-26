package com.iamplatform.servicekit.correlation

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class CorrelationIdTest {

    @Test
    fun `get generates and sticks within the current thread until cleared`() {
        CorrelationId.clear()
        val first = CorrelationId.get()
        val second = CorrelationId.get()
        assertEquals(first, second)

        CorrelationId.clear()
        val third = CorrelationId.get()
        assertNotEquals(first, third)
    }

    @Test
    fun `set overrides whatever would otherwise be generated`() {
        CorrelationId.clear()
        CorrelationId.set("fixed-id")
        assertEquals("fixed-id", CorrelationId.get())
        CorrelationId.clear()
    }
}
