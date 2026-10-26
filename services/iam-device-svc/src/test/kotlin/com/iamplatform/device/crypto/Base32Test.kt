package com.iamplatform.device.crypto

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals

class Base32Test {

    @Test
    fun `matches the RFC 4648 test vector for 'foobar'`() {
        assertEquals("MZXW6YTBOI", Base32.encode("foobar".toByteArray()))
    }

    @Test
    fun `encodes an empty input as an empty string`() {
        assertEquals("", Base32.encode(ByteArray(0)))
    }
}
