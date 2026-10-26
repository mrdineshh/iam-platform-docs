package com.iamplatform.oidc

import java.security.cert.X509Certificate
import java.util.Base64

/**
 * Unsigned IdP metadata -- every field here comes from our own config and
 * signing cert, never from a request, so string templating carries no
 * injection risk (unlike SamlResponseBuilder, which handles the
 * subjectEmail/spEntityId path and uses real DOM construction for exactly
 * that reason). Google Workspace's own SSO setup is manual paste-in
 * (entity ID / SSO URL / certificate fields), not metadata-file upload, so
 * this endpoint is mostly for other SPs and for completeness/inspection.
 */
object SamlMetadataBuilder {
    fun build(entityId: String, ssoUrl: String, certificate: X509Certificate): String {
        val certBase64 = Base64.getEncoder().encodeToString(certificate.encoded)
        return """
            <?xml version="1.0" encoding="UTF-8"?>
            <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="$entityId">
              <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
                <md:KeyDescriptor use="signing">
                  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <ds:X509Data>
                      <ds:X509Certificate>$certBase64</ds:X509Certificate>
                    </ds:X509Data>
                  </ds:KeyInfo>
                </md:KeyDescriptor>
                <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
                <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="$ssoUrl"/>
              </md:IDPSSODescriptor>
            </md:EntityDescriptor>
        """.trimIndent()
    }
}
