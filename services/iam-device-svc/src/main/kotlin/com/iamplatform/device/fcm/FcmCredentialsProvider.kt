package com.iamplatform.device.fcm

import com.google.auth.oauth2.GoogleCredentials
import com.iamplatform.servicekit.vault.OpenBaoClient
import org.springframework.stereotype.Component
import java.io.ByteArrayInputStream
import java.nio.charset.StandardCharsets

/**
 * Loads the Firebase service-account JSON from OpenBao (never from a local
 * file at runtime -- Guardrails Section 4's "no hardcoded secrets" applies
 * equally to "no secret files baked into the image"). One platform-wide
 * Firebase project serves all tenants; the mobile app is the same
 * application regardless of tenant (BUILD_PLAN.md Service 9/12).
 */
@Component
class FcmCredentialsProvider(
    private val openBaoClient: OpenBaoClient,
) {
    @Volatile
    private var cached: GoogleCredentials? = null

    fun get(): GoogleCredentials {
        cached?.let { return it }
        synchronized(this) {
            cached?.let { return it }
            val json = openBaoClient.readSecretOrNull(SECRET_PATH)?.get("json") as? String
                ?: error(
                    "No FCM service-account JSON at OpenBao path '$SECRET_PATH' -- " +
                        "see iam-device-svc/README.md for how to load it.",
                )
            val credentials = GoogleCredentials
                .fromStream(ByteArrayInputStream(json.toByteArray(StandardCharsets.UTF_8)))
                .createScoped(listOf("https://www.googleapis.com/auth/firebase.messaging"))
            cached = credentials
            return credentials
        }
    }

    companion object {
        private const val SECRET_PATH = "fcm-service-account"
    }
}
