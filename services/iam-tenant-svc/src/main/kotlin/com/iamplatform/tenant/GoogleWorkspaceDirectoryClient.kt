package com.iamplatform.tenant

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.springframework.stereotype.Component
import org.springframework.web.client.RestClient
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.security.KeyFactory
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.PKCS8EncodedKeySpec
import java.time.Instant
import java.util.Base64
import javax.imageio.ImageIO

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
 * The Workspace plans an admin can pick for a new user (added 2026-11-04). Every plan lives under
 * the same "Google-Apps" product in Google's Enterprise License Manager API -- only the skuId
 * differs. SKU IDs sourced from Google's own Product and SKU IDs reference page; if a given
 * Workspace account isn't actually entitled to a plan (e.g. a reseller-managed account not sold a
 * particular SKU), assignLicense() surfaces Google's own rejection rather than silently no-op'ing,
 * same as every other best-effort Google call in this class.
 */
enum class GoogleWorkspaceLicensePlan(val skuId: String, val label: String) {
    BUSINESS_STARTER("1010020027", "Business Starter"),
    BUSINESS_STANDARD("1010020028", "Business Standard"),
    BUSINESS_PLUS("1010020025", "Business Plus"),
    ENTERPRISE_STARTER("1010020029", "Enterprise Starter"),
    ENTERPRISE_STANDARD("1010020026", "Enterprise Standard"),
    ENTERPRISE_PLUS("1010020020", "Enterprise Plus"),
    ENTERPRISE_ESSENTIALS("1010060003", "Enterprise Essentials"),
    ENTERPRISE_ESSENTIALS_PLUS("1010060005", "Enterprise Essentials Plus"),
    FRONTLINE_STARTER("1010020030", "Frontline Starter"),
    FRONTLINE_STANDARD("1010020031", "Frontline Standard"),
    ;

    companion object {
        const val PRODUCT_ID = "Google-Apps"
        val DEFAULT = BUSINESS_STARTER
        fun fromSkuId(skuId: String?): GoogleWorkspaceLicensePlan =
            entries.find { it.skuId == skuId } ?: DEFAULT
    }
}

data class OrgUnitEnsureResult(val orgUnitPath: String, val created: Boolean)

/** One row of the read-only directory report (see GoogleWorkspaceDirectoryClient.listUsers). */
data class RemoteGoogleDirectoryUser(
    val primaryEmail: String,
    val fullName: String?,
    val orgUnitPath: String?,
    val suspended: Boolean,
)

private data class GoogleUsersListResponse(val users: List<GoogleUserJson>?, val nextPageToken: String?)
private data class GoogleUserJson(val primaryEmail: String?, val name: GoogleUserNameJson?, val orgUnitPath: String?, val suspended: Boolean?)
private data class GoogleUserNameJson(val fullName: String?)

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
    private val gmailClient = RestClient.builder().baseUrl("https://gmail.googleapis.com").build()
    private val licensingClient = RestClient.builder().baseUrl("https://licensing.googleapis.com").build()
    private val secureRandom = SecureRandom()

    companion object {
        private const val USER_SCOPE = "https://www.googleapis.com/auth/admin.directory.user"
        private const val GMAIL_SEND_SCOPE = "https://www.googleapis.com/auth/gmail.send"
        // Write access to the OU catalog itself -- broader than ORG_UNIT_READONLY_SCOPE below, needed
        // to create a new OU. Kept on its own isolated token request (see ensureOrgUnit), same reasoning
        // as GMAIL_SEND_SCOPE: a missing grant for this must never affect create/suspend/delete/list.
        private const val ORG_UNIT_SCOPE = "https://www.googleapis.com/auth/admin.directory.orgunit"
        // Billing-affecting (assigns a paid Workspace plan to a user) -- kept on its own isolated token
        // request, same reasoning as the other added scopes above: a missing grant here must never
        // affect account creation itself, only the license step that follows it.
        private const val LICENSING_SCOPE = "https://www.googleapis.com/auth/apps.licensing"
    }

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

    /**
     * Pushing an IAM group INTO Google as an OU (the reverse of the OU-sync feature, added
     * 2026-11-03): returns the OU's path, creating a new top-level OU named [name] first if none
     * exists there yet. Uses ORG_UNIT_SCOPE on its own isolated token -- NOT combined with
     * USER_SCOPE -- so this is the only thing that stops working if that scope isn't granted; every
     * existing create/suspend/delete/list call is unaffected either way.
     */
    fun ensureOrgUnit(adminEmail: String, key: GoogleServiceAccountKey, name: String): OrgUnitEnsureResult {
        val accessToken = fetchAccessToken(adminEmail, key, ORG_UNIT_SCOPE)
        val path = "/$name"
        try {
            directoryClient.get()
                .uri("/admin/directory/v1/customer/my_customer/orgunits/{name}", name)
                .header("Authorization", "Bearer $accessToken")
                .retrieve()
                .toBodilessEntity()
            return OrgUnitEnsureResult(path, created = false)
        } catch (ex: org.springframework.web.client.HttpClientErrorException.NotFound) {
            // falls through to create below
        } catch (ex: Exception) {
            throw GoogleProvisioningException("Checking whether the $name org unit exists failed: ${ex.message}")
        }
        try {
            directoryClient.post()
                .uri("/admin/directory/v1/customer/my_customer/orgunits")
                .header("Authorization", "Bearer $accessToken")
                .body(mapOf("name" to name, "parentOrgUnitPath" to "/"))
                .retrieve()
                .toBodilessEntity()
            return OrgUnitEnsureResult(path, created = true)
        } catch (ex: Exception) {
            throw GoogleProvisioningException("Creating the $name org unit failed: ${ex.message}")
        }
    }

    /**
     * Moves an already-existing Google account into [orgUnitPath] -- same USER_SCOPE and
     * fetchAccessToken() as setSuspended above, so this needs no new permission. Returns false when
     * Google has no such user (nothing to move, not an error -- same convention as setSuspended).
     */
    fun moveToOrgUnit(adminEmail: String, key: GoogleServiceAccountKey, primaryEmail: String, orgUnitPath: String): Boolean {
        val accessToken = fetchAccessToken(adminEmail, key)
        try {
            directoryClient.patch()
                .uri("/admin/directory/v1/users/{email}", primaryEmail)
                .header("Authorization", "Bearer $accessToken")
                .body(mapOf("orgUnitPath" to orgUnitPath))
                .retrieve()
                .toBodilessEntity()
            return true
        } catch (ex: org.springframework.web.client.HttpClientErrorException.NotFound) {
            return false
        } catch (ex: Exception) {
            throw GoogleProvisioningException("Moving $primaryEmail to $orgUnitPath failed: ${ex.message}")
        }
    }

    /**
     * Deletes the OU named [name] from Google. Same isolated ORG_UNIT_SCOPE token as ensureOrgUnit.
     * Returns false when there's no such OU (nothing to delete, not an error). Google itself refuses
     * to delete an OU that still has users or child OUs in it -- that comes back as a normal
     * GoogleProvisioningException with Google's own message, not swallowed, so the admin sees exactly
     * why ("move everyone out first") rather than a silent no-op.
     */
    fun deleteOrgUnit(adminEmail: String, key: GoogleServiceAccountKey, name: String): Boolean {
        val accessToken = fetchAccessToken(adminEmail, key, ORG_UNIT_SCOPE)
        try {
            directoryClient.delete()
                .uri("/admin/directory/v1/customer/my_customer/orgunits/{name}", name)
                .header("Authorization", "Bearer $accessToken")
                .retrieve()
                .toBodilessEntity()
            return true
        } catch (ex: org.springframework.web.client.HttpClientErrorException.NotFound) {
            return false
        } catch (ex: Exception) {
            throw GoogleProvisioningException("Deleting the $name org unit failed: ${ex.message}")
        }
    }

    /**
     * Read-only: lists every user already in the domain, with their current OU and status, for the
     * admin console's "Organizational units" report (added 2026-10-30, see docs/DECISIONS.md) -- a
     * live view, nothing is stored in IAM and nothing in Google is changed. Uses the same
     * admin.directory.user scope and the same fetchAccessToken() as every write method above, so this
     * needs no new permission grant. Deliberately does not touch provisionUser, setSuspended,
     * deleteUser, or orgUnitPath/GoogleWorkspaceConfigEntity -- where a NEW account gets created (the
     * tenant's configured OU, e.g. "Ratnesh Test") is entirely unaffected by this method existing.
     */
    fun listUsers(adminEmail: String, key: GoogleServiceAccountKey, domain: String): List<RemoteGoogleDirectoryUser> {
        val accessToken = fetchAccessToken(adminEmail, key)
        val result = mutableListOf<RemoteGoogleDirectoryUser>()
        var pageToken: String? = null
        do {
            val uri = buildString {
                append("/admin/directory/v1/users?domain=${urlEncode(domain)}&maxResults=500")
                pageToken?.let { append("&pageToken=${urlEncode(it)}") }
            }
            val response = try {
                directoryClient.get()
                    .uri(uri)
                    .header("Authorization", "Bearer $accessToken")
                    .retrieve()
                    .body(GoogleUsersListResponse::class.java)
            } catch (ex: Exception) {
                throw GoogleProvisioningException("Google Workspace user listing failed: ${ex.message}")
            }
            response?.users?.forEach { u ->
                val email = u.primaryEmail ?: return@forEach
                result += RemoteGoogleDirectoryUser(email, u.name?.fullName, u.orgUnitPath, u.suspended ?: false)
            }
            pageToken = response?.nextPageToken
        } while (pageToken != null)
        return result
    }

    /**
     * Sends an onboarding email as [adminEmail], with a QR code (for an authenticator app) inline in
     * the body -- used by GoogleWorkspaceOuProvisioningService for newly auto-created accounts.
     * Gmail API (users.messages.send), NOT the Directory API: a completely separate, narrower scope
     * (GMAIL_SEND_SCOPE), fetched on its own token so a problem here can never touch anything
     * create/suspend/delete/list does. The message is a small hand-rolled MIME multipart/related part
     * (HTML body + one inline PNG referenced by Content-ID) -- the standard, widely-supported way to
     * embed an image in an email; a data: URI <img> was considered and rejected, since several mail
     * clients (including Gmail itself, historically) don't reliably render those.
     */
    fun sendEmail(adminEmail: String, key: GoogleServiceAccountKey, to: String, subject: String, htmlBody: String, qrCodeData: String) {
        val accessToken = fetchAccessToken(adminEmail, key, GMAIL_SEND_SCOPE)
        val raw = base64Url(mimeMessage(adminEmail, to, subject, htmlBody, renderQrPng(qrCodeData)).toByteArray(Charsets.UTF_8))
        try {
            gmailClient.post()
                .uri("/gmail/v1/users/me/messages/send")
                .header("Authorization", "Bearer $accessToken")
                .body(mapOf("raw" to raw))
                .retrieve()
                .toBodilessEntity()
        } catch (ex: Exception) {
            throw GoogleProvisioningException("Sending the onboarding email to $to failed: ${ex.message}")
        }
    }

    private fun mimeMessage(from: String, to: String, subject: String, htmlBody: String, qrPngBytes: ByteArray): String {
        val boundary = "qr-${System.nanoTime()}"
        val qrBase64Lines = Base64.getEncoder().encodeToString(qrPngBytes).chunked(76).joinToString("\r\n")
        return buildString {
            append("MIME-Version: 1.0\r\n")
            append("From: $from\r\n")
            append("To: $to\r\n")
            append("Subject: $subject\r\n")
            append("Content-Type: multipart/related; boundary=\"$boundary\"\r\n\r\n")
            append("--$boundary\r\n")
            append("Content-Type: text/html; charset=\"UTF-8\"\r\n\r\n")
            append(htmlBody)
            append("\r\n\r\n--$boundary\r\n")
            append("Content-Type: image/png\r\n")
            append("Content-Transfer-Encoding: base64\r\n")
            append("Content-ID: <qrcode>\r\n")
            append("Content-Disposition: inline; filename=\"qrcode.png\"\r\n\r\n")
            append(qrBase64Lines)
            append("\r\n\r\n--$boundary--")
        }
    }

    /** 2D barcode encoding itself comes from ZXing (see build.gradle.kts); this is just BitMatrix -> PNG bytes. */
    private fun renderQrPng(data: String, size: Int = 260): ByteArray {
        val matrix = QRCodeWriter().encode(data, BarcodeFormat.QR_CODE, size, size)
        val image = BufferedImage(size, size, BufferedImage.TYPE_INT_RGB)
        for (x in 0 until size) {
            for (y in 0 until size) {
                image.setRGB(x, y, if (matrix.get(x, y)) 0x000000 else 0xFFFFFF)
            }
        }
        val out = ByteArrayOutputStream()
        ImageIO.write(image, "png", out)
        return out.toByteArray()
    }

    /**
     * Assigns a paid Workspace plan (a product/SKU pair from Google's Enterprise License Manager API)
     * to a user -- added 2026-11-04 so Create User can offer a plan choice instead of hardcoding
     * Business Starter. Own isolated LICENSING_SCOPE token, same reasoning as every other scope added
     * to this class: a missing grant here only breaks licensing, never account creation itself (see
     * AdminUserController, which calls this as a best-effort step after provisionUser succeeds).
     * Returns false when Google reports the user already holds this exact SKU (409 "already has
     * license") -- not an error, nothing to change. Any other failure (unavailable SKU for this
     * Workspace's plan/billing type, insufficient seats, etc.) surfaces as Google's own message via
     * GoogleProvisioningException rather than being swallowed, so the admin sees why.
     */
    fun assignLicense(adminEmail: String, key: GoogleServiceAccountKey, productId: String, skuId: String, userEmail: String): Boolean {
        val accessToken = fetchAccessToken(adminEmail, key, LICENSING_SCOPE)
        try {
            licensingClient.post()
                .uri("/apps/licensing/v1/product/{productId}/sku/{skuId}/user", productId, skuId)
                .header("Authorization", "Bearer $accessToken")
                .body(mapOf("userId" to userEmail))
                .retrieve()
                .toBodilessEntity()
            return true
        } catch (ex: org.springframework.web.client.HttpClientErrorException.Conflict) {
            return false
        } catch (ex: Exception) {
            throw GoogleProvisioningException("Assigning the Workspace license to $userEmail failed: ${ex.message}")
        }
    }

    // Scope defaults to the Directory API one every existing call site already relied on, so none of
    // them changed when this gained a parameter. sendEmail() below passes a DIFFERENT, narrower scope
    // on its own token request -- never combined with this one -- so a problem with Gmail access can
    // never affect create/suspend/delete/list, and vice versa.
    private fun fetchAccessToken(adminEmail: String, key: GoogleServiceAccountKey, scope: String = USER_SCOPE): String {
        val jwt = signedAssertionJwt(adminEmail, key, scope)
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
    private fun signedAssertionJwt(adminEmail: String, key: GoogleServiceAccountKey, scope: String): String {
        val now = Instant.now()
        val header = mapOf("alg" to "RS256", "typ" to "JWT", "kid" to key.privateKeyId)
        val claims = mapOf(
            "iss" to key.clientEmail,
            "sub" to adminEmail,
            "scope" to scope,
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
