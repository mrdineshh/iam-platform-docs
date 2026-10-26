package com.iamplatform.oidc

import org.w3c.dom.Document
import java.io.ByteArrayOutputStream
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.util.UUID
import javax.xml.crypto.dsig.CanonicalizationMethod
import javax.xml.crypto.dsig.DigestMethod
import javax.xml.crypto.dsig.SignatureMethod
import javax.xml.crypto.dsig.Transform
import javax.xml.crypto.dsig.XMLSignatureFactory
import javax.xml.crypto.dsig.dom.DOMSignContext
import javax.xml.crypto.dsig.spec.TransformParameterSpec
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.OutputKeys
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult

private const val SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
private const val SAMLP_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
private const val XMLNS_NS = "http://www.w3.org/2000/xmlns/"

data class SamlAssertionRequest(
    val idpEntityId: String,
    val spEntityId: String,
    val acsUrl: String,
    val inResponseTo: String?,
    val subjectEmail: String,
    val assertionTtlSeconds: Long,
)

/**
 * Builds a signed SAML 2.0 Response containing exactly one Assertion, per
 * the SP-initiated Web Browser SSO profile (SAML 2.0 Profiles 4.1). Built
 * by hand with plain DOM -- every user-controlled value (subjectEmail,
 * spEntityId, inResponseTo echoed from the request) goes through
 * Element.setTextContent/setAttribute, which escapes automatically, so
 * there's no string-templating XML-injection surface here. The signature
 * itself is produced by the JDK's standard javax.xml.crypto.dsig
 * implementation (not hand-rolled), which is what actually matters for
 * correctness -- canonicalization and digest computation are exactly as
 * fragile to get subtly wrong as the cryptography itself.
 */
object SamlResponseBuilder {
    private val instantFormatter = DateTimeFormatter.ISO_INSTANT

    private val documentBuilderFactory = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
    }

    fun buildSignedResponseXml(request: SamlAssertionRequest, privateKey: PrivateKey, certificate: X509Certificate): String {
        val doc = documentBuilderFactory.newDocumentBuilder().newDocument()
        val now = Instant.now()
        val notBefore = now.minusSeconds(60)
        val notOnOrAfter = now.plusSeconds(request.assertionTtlSeconds)
        val responseId = "_${UUID.randomUUID()}"
        val assertionId = "_${UUID.randomUUID()}"

        val response = doc.createElementNS(SAMLP_NS, "samlp:Response")
        // setAttributeNS with the real xmlns namespace URI, not plain
        // setAttribute. Found live: with plain setAttribute, re-parsing
        // this method's own serialized output and re-validating the
        // signature (in the same JVM, same JDK XML-DSig implementation)
        // failed with a digest mismatch, even though signing itself
        // reported success. Root cause: setAttribute("xmlns:saml", ...)
        // only adds a plain attribute whose name happens to look like a
        // namespace declaration -- it's NOT registered as a real
        // namespace node in the live DOM, so C14N (which looks at actual
        // namespace nodes) renders the live tree differently than it
        // renders a re-parsed copy of the same XML text, where a real
        // parser DOES recognize "xmlns:saml=..." as a true declaration.
        // setAttributeNS with "http://www.w3.org/2000/xmlns/" creates the
        // same true namespace node a parser would have produced, closing
        // that gap at the source so both forms canonicalize identically.
        response.setAttributeNS(XMLNS_NS, "xmlns:samlp", SAMLP_NS)
        response.setAttributeNS(XMLNS_NS, "xmlns:saml", SAML_NS)
        response.setAttribute("ID", responseId)
        response.setAttribute("Version", "2.0")
        response.setAttribute("IssueInstant", instantFormatter.format(now))
        response.setAttribute("Destination", request.acsUrl)
        request.inResponseTo?.let { response.setAttribute("InResponseTo", it) }
        doc.appendChild(response)

        response.appendChild(textElement(doc, SAML_NS, "saml:Issuer", request.idpEntityId))

        val status = doc.createElementNS(SAMLP_NS, "samlp:Status")
        val statusCode = doc.createElementNS(SAMLP_NS, "samlp:StatusCode")
        statusCode.setAttribute("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")
        status.appendChild(statusCode)
        response.appendChild(status)

        val assertion = doc.createElementNS(SAML_NS, "saml:Assertion")
        // Declared explicitly here too (as a true namespace node, see
        // XMLNS_NS comment above), not just inherited from the ancestor
        // <samlp:Response> -- the Assertion, not the whole Response, is
        // what gets digested/signed in isolation via
        // Reference("#$assertionId"), so it needs its own unambiguous,
        // real namespace node rather than relying on inheritance.
        assertion.setAttributeNS(XMLNS_NS, "xmlns:saml", SAML_NS)
        assertion.setAttribute("ID", assertionId)
        // Without this, XML-DSig's Reference("#$assertionId") can't be
        // dereferenced during signing -- a plain DocumentBuilder (no DTD/
        // schema) never infers that an "ID" attribute is actually an
        // XML ID type on its own; this is what tells it to. Found live:
        // signing failed deep inside the JDK's DOMXMLSignature.sign with
        // no useful message otherwise.
        assertion.setIdAttribute("ID", true)
        assertion.setAttribute("Version", "2.0")
        assertion.setAttribute("IssueInstant", instantFormatter.format(now))
        response.appendChild(assertion)

        assertion.appendChild(textElement(doc, SAML_NS, "saml:Issuer", request.idpEntityId))

        val subject = doc.createElementNS(SAML_NS, "saml:Subject")
        val nameId = textElement(doc, SAML_NS, "saml:NameID", request.subjectEmail)
        nameId.setAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
        subject.appendChild(nameId)

        val subjectConfirmation = doc.createElementNS(SAML_NS, "saml:SubjectConfirmation")
        subjectConfirmation.setAttribute("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        val subjectConfirmationData = doc.createElementNS(SAML_NS, "saml:SubjectConfirmationData")
        request.inResponseTo?.let { subjectConfirmationData.setAttribute("InResponseTo", it) }
        subjectConfirmationData.setAttribute("NotOnOrAfter", instantFormatter.format(notOnOrAfter))
        subjectConfirmationData.setAttribute("Recipient", request.acsUrl)
        subjectConfirmation.appendChild(subjectConfirmationData)
        subject.appendChild(subjectConfirmation)
        assertion.appendChild(subject)

        val conditions = doc.createElementNS(SAML_NS, "saml:Conditions")
        conditions.setAttribute("NotBefore", instantFormatter.format(notBefore))
        conditions.setAttribute("NotOnOrAfter", instantFormatter.format(notOnOrAfter))
        val audienceRestriction = doc.createElementNS(SAML_NS, "saml:AudienceRestriction")
        audienceRestriction.appendChild(textElement(doc, SAML_NS, "saml:Audience", request.spEntityId))
        conditions.appendChild(audienceRestriction)
        assertion.appendChild(conditions)

        val authnStatement = doc.createElementNS(SAML_NS, "saml:AuthnStatement")
        authnStatement.setAttribute("AuthnInstant", instantFormatter.format(now))
        authnStatement.setAttribute("SessionIndex", assertionId)
        val authnContext = doc.createElementNS(SAML_NS, "saml:AuthnContext")
        authnContext.appendChild(
            textElement(doc, SAML_NS, "saml:AuthnContextClassRef", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),
        )
        authnStatement.appendChild(authnContext)
        assertion.appendChild(authnStatement)

        signAssertion(assertion, assertionId, insertBeforeSibling = subject, privateKey = privateKey, certificate = certificate)

        return serialize(doc)
    }

    private fun signAssertion(
        assertion: org.w3c.dom.Element,
        assertionId: String,
        insertBeforeSibling: org.w3c.dom.Element,
        privateKey: PrivateKey,
        certificate: X509Certificate,
    ) {
        val sigFactory = XMLSignatureFactory.getInstance("DOM")

        val transforms = listOf(
            sigFactory.newTransform(Transform.ENVELOPED, null as TransformParameterSpec?),
            sigFactory.newTransform(CanonicalizationMethod.EXCLUSIVE, null as TransformParameterSpec?),
        )
        val reference = sigFactory.newReference(
            "#$assertionId",
            sigFactory.newDigestMethod(DigestMethod.SHA256, null),
            transforms,
            null,
            null,
        )
        val signedInfo = sigFactory.newSignedInfo(
            sigFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, null as javax.xml.crypto.dsig.spec.C14NMethodParameterSpec?),
            sigFactory.newSignatureMethod(SignatureMethod.RSA_SHA256, null),
            listOf(reference),
        )

        val keyInfoFactory = sigFactory.keyInfoFactory
        val x509Data = keyInfoFactory.newX509Data(listOf(certificate))
        val keyInfo = keyInfoFactory.newKeyInfo(listOf(x509Data))

        // SAML convention: <ds:Signature> is the sibling immediately after
        // <saml:Issuer> and before <saml:Subject> -- DOMSignContext's
        // "next sibling" controls exactly where among Assertion's existing
        // children the signature gets inserted.
        val signContext = DOMSignContext(privateKey, assertion, insertBeforeSibling)
        sigFactory.newXMLSignature(signedInfo, keyInfo).sign(signContext)
    }

    private fun textElement(doc: Document, ns: String, qualifiedName: String, text: String): org.w3c.dom.Element {
        val el = doc.createElementNS(ns, qualifiedName)
        el.textContent = text
        return el
    }

    private fun serialize(doc: Document): String {
        val output = ByteArrayOutputStream()
        val transformer = TransformerFactory.newInstance().newTransformer()
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no")
        transformer.transform(DOMSource(doc), StreamResult(output))
        return output.toString(Charsets.UTF_8)
    }
}
