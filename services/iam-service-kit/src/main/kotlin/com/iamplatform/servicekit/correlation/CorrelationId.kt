package com.iamplatform.servicekit.correlation

import java.util.UUID

object CorrelationId {
    const val HEADER = "X-Correlation-Id"
    const val MDC_KEY = "correlationId"

    private val current = ThreadLocal<String>()

    fun generate(): String = UUID.randomUUID().toString()

    fun set(value: String) {
        current.set(value)
    }

    fun get(): String = current.get() ?: generate().also { set(it) }

    fun clear() {
        current.remove()
    }
}
