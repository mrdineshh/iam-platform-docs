package com.iamplatform.oidc

import com.iamplatform.oidc.client.IdentityClient
import com.iamplatform.oidc.client.SessionClient
import com.iamplatform.oidc.client.TenantClient
import com.iamplatform.servicekit.audit.ActorType
import com.iamplatform.servicekit.audit.AuditEvent
import com.iamplatform.servicekit.audit.AuditPublisher
import com.iamplatform.servicekit.audit.AuditResult
import com.iamplatform.servicekit.correlation.CorrelationId
import org.springframework.stereotype.Service
import java.net.URLEncoder

class UnknownSamlSpException(entityId: String) : RuntimeException("No SAML SP registered for entity ID '$entityId'")
class SamlRequestNotFoundException : RuntimeException("SAML request unknown or expired")
class SamlSessionInvalidException(message: String) : RuntimeException(message)

data class SamlCompletion(val acsUrl: String, val samlResponseBase64: String, val relayState: String?)

/**
 * SAML 2.0 counterpart to OidcService -- same split responsibility: GET
 * /saml/sso only resolves the SP and hands the browser to iam-login-portal
 * (never checks a password itself, AP-1), POST /saml/complete (called by
 * the portal once it holds a validated session token) is what actually
 * issues the signed assertion. AP-3 applies identically to a SAML SP as
 * to an OIDC client: the portal's own login + this platform's policy
 * engine decide whether a session exists at all; nothing here can issue
 * an assertion without one.
 */
@Service
class SamlService(
    private val tenantClient: TenantClient,
    private val sessionClient: SessionClient,
    private val identityClient: IdentityClient,
    private val requestStore: SamlRequestStore,
    private val signingKeyProvider: SamlSigningKeyProvider,
    private val auditPublisher: AuditPublisher,
    private val oidcProperties: OidcProperties,
    private val samlProperties: SamlProperties,
) {
    private val idpEntityId: String get() = "${oidcProperties.issuer}/saml/metadata"
    private val ssoUrl: String get() = "${oidcProperties.issuer}/saml/sso"

    fun idpInfo(): Triple<String, String, String> {
        val cert = signingKeyProvider.get().certificate
        val pem = buildString {
            append("-----BEGIN CERTIFICATE-----\n")
            append(java.util.Base64.getMimeEncoder(64, byteArrayOf('\n'.code.toByte())).encodeToString(cert.encoded))
            append("\n-----END CERTIFICATE-----\n")
        }
        return Triple(idpEntityId, ssoUrl, pem)
    }

    fun metadataXml(): String = SamlMetadataBuilder.build(idpEntityId, ssoUrl, signingKeyProvider.get().certificate)

    /** GET /saml/sso's success case: where to send the browser to actually log in. */
    fun buildLoginRedirect(samlRequestParam: String, relayState: String?, loginPortalBaseUrl: String): String {
        val parsed = SamlAuthnRequestParser.parse(samlRequestParam)
        val sp = tenantClient.findSamlSpByEntityId(parsed.issuer) ?: throw UnknownSamlSpException(parsed.issuer)
        val tenant = tenantClient.findTenant(sp.tenantId)
            ?: throw UnknownSamlSpException(parsed.issuer)

        val requestId = requestStore.store(
            PendingSamlRequest(
                samlSpId = sp.id,
                tenantId = sp.tenantId,
                spEntityId = sp.spEntityId,
                acsUrl = sp.acsUrl,
                inResponseTo = parsed.id,
                relayState = relayState,
            ),
        )

        val query = "saml_request_id=${encode(requestId)}"
        return if (loginPortalBaseUrl.contains("{subdomain}")) {
            val host = loginPortalBaseUrl.replace("{subdomain}", tenant.subdomain)
            "$host/saml?$query"
        } else {
            "$loginPortalBaseUrl/saml?$query&tenant=${encode(tenant.subdomain)}"
        }
    }

    /**
     * POST /saml/complete: iam-login-portal already authenticated the user
     * against iam-auth-svc (the same precheck/login/2FA flow as the OIDC
     * path -- nothing SAML-specific about *how* someone logs in, only
     * about what happens once they have) and holds a validated session
     * token. Builds and signs the assertion, returns what the portal needs
     * to render the HTTP-POST binding's auto-submitting form.
     */
    fun completeSamlAuthorization(sessionToken: String, samlRequestId: String): SamlCompletion {
        val pending = requestStore.consume(samlRequestId) ?: throw SamlRequestNotFoundException()

        val session = sessionClient.find(sessionToken)
            ?: throw SamlSessionInvalidException("session token unknown or expired")
        if (session.tenantId != pending.tenantId) {
            throw SamlSessionInvalidException("session does not belong to this SP's tenant")
        }
        val user = identityClient.findUser(session.userId)
            ?: throw SamlSessionInvalidException("user for this session no longer exists")

        val signing = signingKeyProvider.get()
        val responseXml = SamlResponseBuilder.buildSignedResponseXml(
            SamlAssertionRequest(
                idpEntityId = idpEntityId,
                spEntityId = pending.spEntityId,
                acsUrl = pending.acsUrl,
                inResponseTo = pending.inResponseTo,
                subjectEmail = user.email,
                assertionTtlSeconds = samlProperties.assertionTtl.seconds,
            ),
            signing.privateKey,
            signing.certificate,
        )

        auditPublisher.publish(
            AuditEvent(
                correlationId = CorrelationId.get(),
                tenantId = pending.tenantId,
                actorType = ActorType.USER,
                actorId = session.userId.toString(),
                action = "saml.assertion_issued",
                result = AuditResult.SUCCESS,
                reason = "spEntityId=${pending.spEntityId}",
            ),
        )

        val base64 = java.util.Base64.getEncoder().encodeToString(responseXml.toByteArray(Charsets.UTF_8))
        return SamlCompletion(pending.acsUrl, base64, pending.relayState)
    }

    private fun encode(value: String): String = URLEncoder.encode(value, "UTF-8")
}
