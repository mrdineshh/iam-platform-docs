package com.iamplatform.servicekit.http

import java.io.File
import java.io.FileInputStream
import java.security.KeyStore
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

/**
 * Builds an SSLContext from the PKCS12 keystore/truststore the shared
 * mTLS entrypoint script (`mtls-entrypoint.sh`, workspace root) prepares
 * at container startup from a cert OpenBao's PKI engine issued. Every
 * outbound call this service makes presents this cert and trusts the
 * platform's internal CA -- see docs/DECISIONS.md, mTLS rollout entry.
 *
 * Returns null (falls back to plain HTTP, unchanged prior behavior) if
 * those files don't exist -- lets a service with no REST callers of its
 * own (iam-audit-svc, Kafka-consumer only) skip mTLS entirely with zero
 * code branching at each call site.
 */
object MtlsSslContext {
    private const val KEYSTORE_PATH = "/mtls/keystore.p12"
    private const val TRUSTSTORE_PATH = "/mtls/truststore.p12"
    private const val STORE_PASSWORD = "changeit"

    val instance: SSLContext? by lazy { build() }

    private fun build(): SSLContext? {
        val keystoreFile = File(KEYSTORE_PATH)
        val truststoreFile = File(TRUSTSTORE_PATH)
        if (!keystoreFile.exists() || !truststoreFile.exists()) return null

        val keyStore = KeyStore.getInstance("PKCS12")
        FileInputStream(keystoreFile).use { keyStore.load(it, STORE_PASSWORD.toCharArray()) }
        val keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm())
        keyManagerFactory.init(keyStore, STORE_PASSWORD.toCharArray())

        val trustStore = KeyStore.getInstance("PKCS12")
        FileInputStream(truststoreFile).use { trustStore.load(it, STORE_PASSWORD.toCharArray()) }
        val trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
        trustManagerFactory.init(trustStore)

        val sslContext = SSLContext.getInstance("TLS")
        sslContext.init(keyManagerFactory.keyManagers, trustManagerFactory.trustManagers, null)
        return sslContext
    }
}
