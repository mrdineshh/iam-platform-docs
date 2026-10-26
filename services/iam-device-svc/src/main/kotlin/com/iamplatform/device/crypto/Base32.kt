package com.iamplatform.device.crypto

/**
 * RFC 4648 base32 (no padding) -- the format Google Authenticator and every
 * other TOTP app expects for the secret in an otpauth:// URI. Not in the
 * JDK (only Base64/Base16 are), and small enough not to warrant a dependency.
 */
object Base32 {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

    fun encode(data: ByteArray): String {
        if (data.isEmpty()) return ""
        val output = StringBuilder((data.size * 8 + 4) / 5)
        var buffer = 0
        var bitsLeft = 0
        for (byte in data) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                bitsLeft -= 5
                output.append(ALPHABET[(buffer shr bitsLeft) and 0x1F])
            }
        }
        if (bitsLeft > 0) {
            output.append(ALPHABET[(buffer shl (5 - bitsLeft)) and 0x1F])
        }
        return output.toString()
    }
}
