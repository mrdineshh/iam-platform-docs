package com.iamplatform.device.crypto

import org.junit.jupiter.api.Test
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TotpGeneratorTest {

    private val rfc6238Secret = "12345678901234567890".toByteArray()

    @Test
    fun `matches the RFC 6238 published test vector at T=59s`() {
        val code = TotpGenerator.generateCode(rfc6238Secret, Instant.ofEpochSecond(59), stepSeconds = 30, digits = 8)
        assertEquals("94287082", code)
    }

    @Test
    fun `matches the RFC 6238 published test vector at T=1111111109s`() {
        val code = TotpGenerator.generateCode(rfc6238Secret, Instant.ofEpochSecond(1111111109), stepSeconds = 30, digits = 8)
        assertEquals("07081804", code)
    }

    @Test
    fun `verifyCode accepts a code generated for the exact same step`() {
        val secret = ByteArray(20) { it.toByte() }
        val now = Instant.now()
        val code = TotpGenerator.generateCode(secret, now, stepSeconds = 30, digits = 6)
        assertTrue(TotpGenerator.verifyCode(secret, code, now, stepSeconds = 30, digits = 6, driftWindowSteps = 1))
    }

    @Test
    fun `verifyCode accepts a code from one step in the past, within the drift window`() {
        val secret = ByteArray(20) { it.toByte() }
        val now = Instant.now()
        val previousStepCode = TotpGenerator.generateCode(secret, now.minusSeconds(30), stepSeconds = 30, digits = 6)
        assertTrue(TotpGenerator.verifyCode(secret, previousStepCode, now, stepSeconds = 30, digits = 6, driftWindowSteps = 1))
    }

    @Test
    fun `verifyCode rejects a code two steps in the past, outside the drift window`() {
        val secret = ByteArray(20) { it.toByte() }
        val now = Instant.now()
        val staleCode = TotpGenerator.generateCode(secret, now.minusSeconds(60), stepSeconds = 30, digits = 6)
        assertFalse(TotpGenerator.verifyCode(secret, staleCode, now, stepSeconds = 30, digits = 6, driftWindowSteps = 1))
    }

    @Test
    fun `verifyCode rejects a wrong code`() {
        val secret = ByteArray(20) { it.toByte() }
        val now = Instant.now()
        val correct = TotpGenerator.generateCode(secret, now, stepSeconds = 30, digits = 6)
        val wrong = ((correct.toInt() + 1) % 1_000_000).toString().padStart(6, '0')
        assertFalse(TotpGenerator.verifyCode(secret, wrong, now, stepSeconds = 30, digits = 6, driftWindowSteps = 1))
    }
}
