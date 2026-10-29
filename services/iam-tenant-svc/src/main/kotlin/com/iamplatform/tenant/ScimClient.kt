package com.iamplatform.tenant

import org.springframework.http.HttpStatusCode
import org.springframework.http.MediaType
import org.springframework.http.client.JdkClientHttpRequestFactory
import org.springframework.stereotype.Component
import org.springframework.web.client.HttpStatusCodeException
import org.springframework.web.client.ResourceAccessException
import org.springframework.web.client.RestClient
import java.net.http.HttpClient
import java.time.Duration

/** What the platform tells an app about a user (SCIM core User schema, RFC 7643). */
data class ScimUserSpec(
    val userName: String,
    val externalId: String,
    val displayName: String,
    val givenName: String,
    val familyName: String,
    val active: Boolean,
)

class ScimException(
    message: String,
    val status: Int? = null,
) : RuntimeException(message) {
    val notFound: Boolean get() = status == 404
    val conflict: Boolean get() = status == 409
}

private val SCIM_JSON = MediaType.parseMediaType("application/scim+json")
private const val USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
private const val PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

/**
 * SCIM 2.0 (RFC 7643/7644) client: create, find, activate/suspend and delete
 * a user in an app that exposes a SCIM endpoint. Hand-rolled on RestClient
 * (no SCIM library) because the whole integration is five small calls.
 *
 * Every call re-validates the target URL (see [OutboundUrlGuard]), never
 * follows redirects, and has a connect and read timeout, so a slow or hostile
 * endpoint cannot hang or redirect the platform. Tokens are only ever sent in
 * the Authorization header and never logged.
 */
@Component
class ScimClient(
    private val urlGuard: OutboundUrlGuard,
) {
    private val requestFactory = JdkClientHttpRequestFactory(
        HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(Duration.ofSeconds(5))
            .build(),
    // 30s, not 10: apps that scale to zero (Cloud Run and similar) can take ~11s to answer the first
    // call after idling. A shorter wait reports "Failed" for a change the app then applies anyway.
    ).apply { setReadTimeout(Duration.ofSeconds(30)) }

    /** Reads the app's ServiceProviderConfig: proves the URL and token work. */
    fun testConnection(baseUrl: String, token: String) {
        call { client(baseUrl, token).get().uri("/ServiceProviderConfig").retrieve().toBodilessEntity() }
    }

    /** Creates the user; returns the app's own id for it. A 409 surfaces as [ScimException.conflict]. */
    fun createUser(baseUrl: String, token: String, user: ScimUserSpec): String {
        val body = mapOf(
            "schemas" to listOf(USER_SCHEMA),
            "externalId" to user.externalId,
            "userName" to user.userName,
            "displayName" to user.displayName,
            "name" to mapOf("givenName" to user.givenName, "familyName" to user.familyName),
            "emails" to listOf(mapOf("value" to user.userName, "primary" to true)),
            "active" to user.active,
        )
        val response = call {
            client(baseUrl, token).post().uri("/Users").contentType(SCIM_JSON).body(body).retrieve().body(Map::class.java)
        }
        return response?.get("id")?.toString()?.takeIf { it.isNotBlank() }
            ?: throw ScimException("The app created the user but did not return an id.")
    }

    /** Looks a user up by userName (filter eq); null when the app has no such user. */
    fun findIdByUserName(baseUrl: String, token: String, userName: String): String? {
        require(!userName.contains('"') && !userName.contains('\\')) { "unsupported characters in userName" }
        val response = call {
            client(baseUrl, token).get()
                .uri { b -> b.path("/Users").queryParam("filter", "{f}").build(mapOf("f" to "userName eq \"$userName\"")) }
                .retrieve()
                .body(Map::class.java)
        }
        val resources = response?.get("Resources") as? List<*> ?: return null
        val first = resources.firstOrNull() as? Map<*, *> ?: return null
        return first["id"]?.toString()
    }

    /**
     * Sets active true/false (suspend or reactivate). Uses a PATCH, which every
     * SCIM server must support for the "active" attribute; a server that only
     * implements full replacement (405/501) gets a GET then PUT instead.
     */
    fun setActive(baseUrl: String, token: String, id: String, active: Boolean) {
        val patch = mapOf(
            "schemas" to listOf(PATCH_SCHEMA),
            "Operations" to listOf(mapOf("op" to "replace", "path" to "active", "value" to active)),
        )
        try {
            call { client(baseUrl, token).patch().uri("/Users/{id}", id).contentType(SCIM_JSON).body(patch).retrieve().toBodilessEntity() }
        } catch (ex: ScimException) {
            if (ex.status != 405 && ex.status != 501) throw ex
            val current = call { client(baseUrl, token).get().uri("/Users/{id}", id).retrieve().body(Map::class.java) }
                ?: throw ScimException("The app returned no user to update.")
            val updated = current.entries.associate { it.key.toString() to it.value }.toMutableMap()
            updated["active"] = active
            call { client(baseUrl, token).put().uri("/Users/{id}", id).contentType(SCIM_JSON).body(updated).retrieve().toBodilessEntity() }
        }
    }

    /** Deletes the user. Already gone (404) counts as done. */
    fun deleteUser(baseUrl: String, token: String, id: String) {
        try {
            call { client(baseUrl, token).delete().uri("/Users/{id}", id).retrieve().toBodilessEntity() }
        } catch (ex: ScimException) {
            if (!ex.notFound) throw ex
        }
    }

    private fun client(baseUrl: String, token: String): RestClient =
        RestClient.builder()
            .requestFactory(requestFactory)
            .baseUrl(urlGuard.validate(baseUrl).toString().trimEnd('/'))
            .defaultHeader("Authorization", "Bearer $token")
            .defaultHeader("Accept", "application/scim+json, application/json")
            .build()

    private fun <T> call(block: () -> T): T =
        try {
            block()
        } catch (ex: InvalidProvisioningTargetException) {
            throw ScimException(ex.message ?: "The target URL is not allowed.")
        } catch (ex: HttpStatusCodeException) {
            throw ScimException(describe(ex.statusCode, ex.responseBodyAsString), ex.statusCode.value())
        } catch (ex: ResourceAccessException) {
            throw ScimException("Could not reach the app: ${ex.cause?.message ?: ex.message}")
        }

    private fun describe(status: HttpStatusCode, body: String): String {
        val hint = when (status.value()) {
            401, 403 -> "the app rejected the access token"
            404 -> "not found"
            409 -> "already exists"
            429 -> "the app is rate limiting requests"
            else -> null
        }
        val snippet = body.trim().replace(Regex("\\s+"), " ").take(160)
        return buildString {
            append("The app answered HTTP ${status.value()}")
            if (hint != null) append(" ($hint)")
            if (snippet.isNotEmpty()) append(": $snippet")
        }
    }
}
