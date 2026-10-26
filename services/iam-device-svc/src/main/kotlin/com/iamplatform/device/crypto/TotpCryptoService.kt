package com.iamplatform.device.crypto

import org.springframework.stereotype.Component
import java.security.SecureRandom
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class EncryptedSecret(val ciphertext: ByteArray, val nonce: ByteArray)

@Component
class TotpCryptoService(
    private val dekProvider: TotpDekProvider,
) {
    fun encrypt(tenantId: UUID, plaintext: ByteArray): EncryptedSecret {
        val nonce = ByteArray(GCM_NONCE_LENGTH_BYTES)
        SecureRandom().nextBytes(nonce)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keyFor(tenantId), GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce))
        return EncryptedSecret(cipher.doFinal(plaintext), nonce)
    }

    fun decrypt(tenantId: UUID, ciphertext: ByteArray, nonce: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, keyFor(tenantId), GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce))
        return cipher.doFinal(ciphertext)
    }

    private fun keyFor(tenantId: UUID) = SecretKeySpec(dekProvider.get(tenantId), "AES")

    companion object {
        private const val GCM_NONCE_LENGTH_BYTES = 12
        private const val GCM_TAG_LENGTH_BITS = 128
    }
}
