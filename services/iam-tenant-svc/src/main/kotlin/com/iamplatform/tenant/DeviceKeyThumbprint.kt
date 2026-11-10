package com.iamplatform.tenant

import java.security.MessageDigest
import java.util.Base64

/**
 * base64url (no padding) SHA-256 over a device public key's X.509 SubjectPublicKeyInfo DER bytes --
 * the same "S256" construction PKCE uses for its code challenge (RFC 7636 Section 4.2). The Rust
 * agent's key_provider::key_thumbprint computes the identical value; both sides pin the same test
 * vector (SHA-256 of "abc") so a drift between them fails a unit test rather than every enrollment.
 */
object DeviceKeyThumbprint {
    fun of(publicKeyDer: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(publicKeyDer))

    /** Constant-time, so a mismatch can't be narrowed down byte by byte via response timing. */
    fun matches(expected: String, actual: String): Boolean =
        MessageDigest.isEqual(expected.toByteArray(Charsets.US_ASCII), actual.toByteArray(Charsets.US_ASCII))
}
