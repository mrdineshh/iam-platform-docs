package com.iamplatform.tenant

import org.springframework.stereotype.Component
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * Verifies a device's proof-of-possession signature against its registered
 * public key -- the cryptographic half of Section 4.2's trust rule ("the
 * device must prove possession of its registered private key"). Supports
 * every key type the Rust agent's key-provider crate can produce (Section
 * 5.3): hardware-backed RSA/ECDSA via TPM/CNG, or software-backed Ed25519.
 * Public keys are always sent/stored X.509 SubjectPublicKeyInfo DER,
 * base64-encoded -- the standard interchange format, not a bespoke one.
 */
@Component
class DeviceSignatureVerifier {

    fun verify(publicKeyBase64: String, keyAlgorithm: String, signedData: ByteArray, signatureBase64: String): Boolean {
        val publicKey = decodePublicKey(publicKeyBase64, keyAlgorithm)
        val signature = try {
            Base64.getDecoder().decode(signatureBase64)
        } catch (ex: IllegalArgumentException) {
            return false
        }
        val signatureAlgorithm = when (keyAlgorithm) {
            "RSA2048", "RSA4096" -> "SHA256withRSA"
            // Windows CNG (the TPM path) signs ECDSA P-256 as the raw 64-byte r||s pair (IEEE P1363); Java's plain
            // "SHA256withECDSA" only reads ASN.1 DER. An r||s pair is always exactly 64 bytes, a DER one never is
            // (it starts with 0x30 and is 70-72 bytes), so the length alone picks the right reader.
            "ECDSA_P256" -> if (signature.size == 64) "SHA256withECDSAinP1363Format" else "SHA256withECDSA"
            "ED25519" -> "Ed25519"
            else -> throw DeviceProofOfPossessionException("Unsupported key algorithm: $keyAlgorithm")
        }
        return try {
            Signature.getInstance(signatureAlgorithm).apply {
                initVerify(publicKey)
                update(signedData)
            }.verify(signature)
        } catch (ex: Exception) {
            false
        }
    }

    private fun decodePublicKey(publicKeyBase64: String, keyAlgorithm: String): PublicKey {
        val keyFactoryAlgorithm = when (keyAlgorithm) {
            "RSA2048", "RSA4096" -> "RSA"
            "ECDSA_P256" -> "EC"
            "ED25519" -> "Ed25519"
            else -> throw DeviceProofOfPossessionException("Unsupported key algorithm: $keyAlgorithm")
        }
        return try {
            val bytes = Base64.getDecoder().decode(publicKeyBase64)
            KeyFactory.getInstance(keyFactoryAlgorithm).generatePublic(X509EncodedKeySpec(bytes))
        } catch (ex: Exception) {
            throw DeviceProofOfPossessionException("Malformed device public key: ${ex.message}")
        }
    }
}
