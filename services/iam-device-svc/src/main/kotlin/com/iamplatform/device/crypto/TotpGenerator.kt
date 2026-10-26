package com.iamplatform.device.crypto

import java.nio.ByteBuffer
import java.time.Instant
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * RFC 6238 TOTP over RFC 4226 HOTP. Hand-rolled rather than a new dependency
 * (Guardrails Tier-3 rule on new third-party deps) -- the algorithm is ~20
 * lines and long-standardized, lower risk than it looks.
 */
object TotpGenerator {

    fun generateCode(secret: ByteArray, timestamp: Instant, stepSeconds: Long, digits: Int): String =
        hotp(secret, timestamp.epochSecond / stepSeconds, digits)

    /** Accepts a code valid at the current step or within +-[driftWindowSteps] steps, for clock drift. */
    fun verifyCode(secret: ByteArray, code: String, timestamp: Instant, stepSeconds: Long, digits: Int, driftWindowSteps: Int): Boolean {
        val currentStep = timestamp.epochSecond / stepSeconds
        for (offset in -driftWindowSteps..driftWindowSteps) {
            if (hotp(secret, currentStep + offset, digits) == code) return true
        }
        return false
    }

    private fun hotp(secret: ByteArray, counter: Long, digits: Int): String {
        val counterBytes = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(secret, "HmacSHA1"))
        val hash = mac.doFinal(counterBytes)

        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)

        val modulus = Math.pow(10.0, digits.toDouble()).toInt()
        return (binary % modulus).toString().padStart(digits, '0')
    }
}
