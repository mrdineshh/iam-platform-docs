package com.iamplatform.tenant

import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64

/** The three fields actually needed from a Google service account JSON key file. */
data class GoogleServiceAccountKey(
    val clientEmail: String,
    val privateKey: String,
    val privateKeyId: String,
)

data class ProvisionGoogleUserRequest(
    val domain: String,
    val adminEmail: String,
    val orgUnitPath: String?,
    val serviceAccountKey: GoogleServiceAccountKey,
    val primaryEmail: String,
    val givenName: String,
    val familyName: String,
)

class GoogleProvisioningException(message: String) : RuntimeException(message)

/**
 * True when [email] is on the Google Workspace domain this tenant configured.
 * An address on any other domain cannot exist in that Workspace, and Google
 * answers 403 "Not Authorized" for it, so callers skip it rather than report
 * a failure.
 */
fun ProvisionGoogleUserRequest.manages(email: String): Boolean =
    email.substringAfterLast('@', "").equals(domain, ignoreCase = true)

/**
 * Admin SDK Directory API client, used to auto-create a matching Google
 * Workspace account whenever a user is created on this platform (added
 * 2026-10-26, see docs/DECISIONS.md). Hand-rolled JWT + OAuth2 exchange
 * rather than Google's own Java client library -- the whole integration is
 * one API call (users.insert), and that library pulls in a large transitive
 * dependency tree for that single use, same "avoid an oversized dependency
 * for a small, well-documented protocol" reasoning as SamlResponseBuilder's
 * hand-rolled XML-DSig instead of OpenSAML.
 *
 * Domain-wide delegation background: a Workspace admin must have already
 * authorized this service account (by its client ID) in the Workspace
 * Admin console (Security -> API controls -> Domain-wide delegation) with
 * the admin.directory.user scope. The service account then "impersonates"
 * [adminEmail] (a real super admin) on every call -- Google requires a real
 * identity to act as, a service account can't manage Directory data as
 * itself.
 */
@Component
class GoogleWorkspaceDirectoryClient {
    private val tokenClient = RestClient.builder().baseUrl("https://oauth2.googleapis.com").build()
    private val directoryClient = RestClient.builder().baseUrl("https://admin.googleapis.com").build()
    private val secureRandom = SecureRandom()

    /**
     * Creates the Workspace account with a random password the admin never
     * needs to know -- see this class's own doc comment and
     * AdminUserController for why: once the account's OU is on an SSO
     * profile in redirect mode, Google never checks this password for
     * normal sign-in at all. changePasswordAtNextLogin=false and an
     * already-assigned orgUnitPath together are what let a brand-new
     * account skip the "must complete one direct Google sign-in first"
     * friction this engagement hit repeatedly doing this by hand.
     */
    fun provisionUser(request: ProvisionGoogleUserRequest): String {
        val accessToken = fetchAccessToken(request.adminEmail, request.serviceAccountKey)
        val password = generatePassword()

        val body = buildMap<String, Any?> {
            put("primaryEmail", request.primaryEmail)
            put("name", mapOf("givenName" to request.givenName, "familyName" to request.familyName))
            put("password", password)
            put("changePasswordAtNextLogin", false)
            request.orgUnitPath?.let { put("orgUnitPath", it) }
        }

        try {
            directoryClient.post()
                .uri("/admin/directory/v1/users")
                .header("Authorization", "Bearer $accessToken")
                .body(body)
                .retrieve()
                .toBodilessEntity()
        } catch (ex: Exception) {
            throw GoogleProvisioningException("Google Workspace user creation failed: ${ex.message}")
        }

        return password
    }

    /**
     * Added 2026-10-26 (docs/DECISIONS.md) so "delete user" actually means
     * deleted everywhere, not just on this platform -- the explicit ask
     * that surfaced this gap. Deletes outright (Directory API's
     * users.delete), not a suspend -- matches this platform's own
     * deleteUser semantics (hard delete, not a status flag). Best-effort
     * from the caller's point of view (AdminUserController never fails
     * the platform-side deletion over this), same reasoning as
     * provisionUser not blocking creation.
     */
    fun deleteUser(adminEmail: String, serviceAccountKey: GoogleServiceAccountKey, primaryEmail: String) {
        val accessToken = fetchAccessToken(adminEmail, serviceAccountKey)
        try {
            directoryClient.delete()
                .uri("/admin/directory/v1/users/{email}", primaryEmail)
                .header("Authorization", "Bearer $accessToken")
                .retrieve()
                .toBodilessEntity()
        } catch (ex: Exception) {
            throw GoogleProvisioningException("Google Workspace user deletion failed: ${ex.message}")
        }
    }

    /**
     * Suspends or reactivates the Google account (Directory API users.patch,
     * `suspended`). A suspended Google user cannot sign in to any Google
     * service, including through this platform's SSO. Returns false when Google
     * has no such user (nothing to change), true when it was applied.
     */
    fun setSuspended(adminEmail: String, serviceAccountKey: GoogleServiceAccountKey, primaryEmail: String, suspended: Boolean): Boolean {
        val accessToken = fetchAccessToken(adminEmail, serviceAccountKey)
        try {
            directoryClient.patch()
                .uri("/admin/directory/v1/users/{email}", primaryEmail)
                .header("Authorization", "Bearer $accessToken")
                .body(mapOf("suspended" to suspended))
                .retrieve()
                .toBodilessEntity()
            return true
        } catch (ex: org.springframework.web.client.HttpClientErrorException.NotFound) {
            return false
        } catch (ex: Exception) {
            val verb = if (suspended) "suspension" else "reactivation"
            throw GoogleProvisioningException("Google Workspace user $verb failed: ${ex.message}")
        }
    }

    private fun fetchAccessToken(adminEmail: String, key: GoogleServiceAccountKey): String {
        val jwt = signedAssertionJwt(adminEmail, key)
        val response = tokenClient.post()
            .uri("/token")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(
                "grant_type=${urlEncode("urn:ietf:params:oauth:grant-type:jwt-bearer")}" +
                    "&assertion=${urlEncode(jwt)}",
            )
            .retrieve()
            .body(TokenResponse::class.java)
            ?: throw GoogleProvisioningException("Google token endpoint returned no body")

        return response.access_token
            ?: throw GoogleProvisioningException("Google token endpoint response had no access_token")
    }

    // Field named to match Google's JSON response verbatim (snake_case),
    // avoiding any dependency on a particular Jackson naming-strategy
    // configuration being active.
    private data class TokenResponse(val access_token: String? = null)

    // RFC 7523 JWT bearer assertion for a service account with domain-wide
    // delegation: "sub" is the impersonated admin, not the service account
    // itself -- that's what makes this a Directory API call made "as" a
    // real Workspace admin rather than as the service account's own
    // (permissionless, for Directory data) identity.
    private fun signedAssertionJwt(adminEmail: String, key: GoogleServiceAccountKey): String {
        val now = Instant.now()
        val header = mapOf("alg" to "RS256", "typ" to "JWT", "kid" to key.privateKeyId)
        val claims = mapOf(
            "iss" to key.clientEmail,
            "sub" to adminEmail,
            "scope" to "https://www.googleapis.com/auth/admin.directory.user",
            "aud" to "https://oauth2.googleapis.com/token",
            "iat" to now.epochSecond,
            "exp" to now.plusSeconds(3600).epochSecond,
        )

        val headerB64 = base64Url(flatJson(header).toByteArray(Charsets.UTF_8))
        val claimsB64 = base64Url(flatJson(claims).toByteArray(Charsets.UTF_8))
        val signingInput = "$headerB64.$claimsB64"

        val privateKey = parsePrivateKey(key.privateKey)
        val signature = Signature.getInstance("SHA256withRSA").apply {
            initSign(privateKey)
            update(signingInput.toByteArray(Charsets.UTF_8))
        }.sign()

        return "$signingInput.${base64Url(signature)}"
    }

    private fun parsePrivateKey(pem: String): PrivateKey {
        val cleaned = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace("\\n", "")
            .replace("\n", "")
            .trim()
        val keyBytes = Base64.getDecoder().decode(cleaned)
        return KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyBytes))
    }

    // Minimal hand-rolled JSON for the JWT header/claims only (both always
    // a flat map of string/number values -- never nested, never needs
    // escaping beyond quotes/backslashes) -- not a general-purpose encoder,
    // deliberately: the actual Directory API request body below goes
    // through Spring's own configured JSON converter instead, same as
    // every other outbound call in this codebase.
    private fun flatJson(fields: Map<String, Any>): String =
        fields.entries.joinToString(",", prefix = "{", postfix = "}") { (key, value) ->
            val jsonValue = when (value) {
                is Number, is Boolean -> value.toString()
                else -> "\"${value.toString().replace("\\", "\\\\").replace("\"", "\\\"")}\""
            }
            "\"$key\":$jsonValue"
        }

    private fun base64Url(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

    private fun urlEncode(value: String): String = java.net.URLEncoder.encode(value, "UTF-8")

    // 24 random bytes, base64 -- never shown to or typed by anyone (see
    // this class's doc comment); only needs to satisfy Google's own
    // password-strength requirement at creation time.
    private fun generatePassword(): String {
        val bytes = ByteArray(24)
        secureRandom.nextBytes(bytes)
        return Base64.getEncoder().encodeToString(bytes)
    }
}
