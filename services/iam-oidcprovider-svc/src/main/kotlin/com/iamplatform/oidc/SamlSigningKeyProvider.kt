package com.iamplatform.oidc

import com.iamplatform.servicekit.vault.OpenBaoClient
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import org.springframework.stereotype.Component
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.Security
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Duration
import java.time.Instant
import java.util.Base64
import java.util.Date

data class SamlSigningMaterial(val privateKey: PrivateKey, val certificate: X509Certificate)

/**
 * Get-or-create platform-wide RSA keypair + self-signed X.509 certificate
 * for signing SAML assertions -- same OpenBao get-or-create pattern as
 * OidcSigningKeyProvider (the OIDC equivalent), just storing a PEM cert
 * instead of a JWK since SAML's whole trust model (and every SP's config
 * UI, including Google Workspace's) expects an X.509 certificate, not a
 * JWK. One keypair, not rotated -- same MVP-TEMPORARY tradeoff the OIDC
 * signing key already documents.
 */
@Component
class SamlSigningKeyProvider(
    private val openBaoClient: OpenBaoClient,
) {
    init {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(org.bouncycastle.jce.provider.BouncyCastleProvider())
        }
    }

    @Volatile
    private var cached: SamlSigningMaterial? = null

    fun get(): SamlSigningMaterial {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val material = load() ?: generateAndStore()
            cached = material
            return material
        }
    }

    private fun load(): SamlSigningMaterial? {
        val secret = openBaoClient.readSecretOrNull(KEY_PATH) ?: return null
        val keyBytes = Base64.getDecoder().decode(secret["privateKey"] as String)
        val certBytes = Base64.getDecoder().decode(secret["certificate"] as String)

        val privateKey = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyBytes))
        val cert = java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(certBytes.inputStream()) as X509Certificate
        return SamlSigningMaterial(privateKey, cert)
    }

    private fun generateAndStore(): SamlSigningMaterial {
        val keyPairGenerator = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }
        val keyPair = keyPairGenerator.generateKeyPair()

        val now = Instant.now()
        val subject = X500Name("CN=IAM Platform SAML IdP")
        // 63 bits, not 64 -- BigInteger(64, random) can produce a value
        // whose high bit lands exactly on a byte boundary, which some
        // strict X.509 parsers (found live: Python's `cryptography`/
        // signxml) read as a negative/non-positive DER INTEGER even
        // though RFC 5280 requires serial numbers to be positive. One bit
        // of headroom avoids the ambiguity entirely.
        val serial = BigInteger(63, java.security.SecureRandom())
        val builder: X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
            subject, serial,
            Date.from(now.minus(Duration.ofMinutes(5))),
            // 10-year validity -- MVP-TEMPORARY, same no-rotation tradeoff as
            // the OIDC signing key; a real deployment would rotate this.
            Date.from(now.plus(Duration.ofDays(3650))),
            subject, keyPair.public,
        )
        // Required by strict SP-side cert validation (found live: signxml
        // rejected the cert for missing this extension) -- a signing-only
        // cert should declare exactly that usage anyway, not just happen
        // to work without it.
        builder.addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature or KeyUsage.nonRepudiation))
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
        val cert = JcaX509CertificateConverter().getCertificate(builder.build(signer))

        openBaoClient.writeSecret(
            KEY_PATH,
            mapOf(
                "privateKey" to Base64.getEncoder().encodeToString(keyPair.private.encoded),
                "certificate" to Base64.getEncoder().encodeToString(cert.encoded),
            ),
        )
        return SamlSigningMaterial(keyPair.private, cert)
    }

    companion object {
        private const val KEY_PATH = "saml-signing-key"
    }
}
