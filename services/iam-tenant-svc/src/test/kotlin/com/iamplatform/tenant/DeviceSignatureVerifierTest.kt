package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeviceSignatureVerifierTest {

    private val verifier = DeviceSignatureVerifier()
    private val data = "device:2026-11-17T10:00:00Z".toByteArray()

    private fun p256(): KeyPair = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()
    private fun spki(k: KeyPair): String = Base64.getEncoder().encodeToString(k.public.encoded)

    private fun sign(k: KeyPair, algorithm: String, bytes: ByteArray = data): String =
        Base64.getEncoder().encodeToString(Signature.getInstance(algorithm).apply { initSign(k.private); update(bytes) }.sign())

    @Test
    fun `an ECDSA P-256 signature in the raw r-s form Windows CNG produces verifies`() {
        val key = p256()
        val signature = sign(key, "SHA256withECDSAinP1363Format")
        assertEquals(64, Base64.getDecoder().decode(signature).size)
        assertTrue(verifier.verify(spki(key), "ECDSA_P256", data, signature))
    }

    @Test
    fun `an ECDSA P-256 signature in DER form still verifies`() {
        val key = p256()
        val signature = sign(key, "SHA256withECDSA")
        assertTrue(Base64.getDecoder().decode(signature).size != 64)
        assertTrue(verifier.verify(spki(key), "ECDSA_P256", data, signature))
    }

    @Test
    fun `a raw ECDSA signature over different data, or from another key, does not verify`() {
        val key = p256()
        assertFalse(verifier.verify(spki(key), "ECDSA_P256", data, sign(key, "SHA256withECDSAinP1363Format", "other".toByteArray())))
        assertFalse(verifier.verify(spki(key), "ECDSA_P256", data, sign(p256(), "SHA256withECDSAinP1363Format")))
    }

    @Test
    fun `garbage in the signature field is a plain no, not an error`() {
        val key = p256()
        assertFalse(verifier.verify(spki(key), "ECDSA_P256", data, "!!not base64!!"))
        assertFalse(verifier.verify(spki(key), "ECDSA_P256", data, Base64.getEncoder().encodeToString(ByteArray(64))))
        assertFalse(verifier.verify(spki(key), "ECDSA_P256", data, ""))
    }

    @Test
    fun `Ed25519, the existing software key type, is unchanged`() {
        val key = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val signature = sign(key, "Ed25519")
        assertTrue(verifier.verify(spki(key), "ED25519", data, signature))
        assertFalse(verifier.verify(spki(key), "ED25519", "tampered".toByteArray(), signature))
    }
}
