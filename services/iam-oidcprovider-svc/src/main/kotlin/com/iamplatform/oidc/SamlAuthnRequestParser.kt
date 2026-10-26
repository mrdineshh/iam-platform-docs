package com.iamplatform.oidc

import org.w3c.dom.Element
import java.io.ByteArrayInputStream
import java.util.Base64
import java.util.zip.Inflater
import java.util.zip.InflaterInputStream
import javax.xml.parsers.DocumentBuilderFactory

data class ParsedAuthnRequest(val id: String, val issuer: String)

class InvalidSamlRequestException(message: String) : RuntimeException(message)

/**
 * HTTP-Redirect binding (SAML 2.0 Bindings 3.4): SAMLRequest is base64 of
 * *raw* DEFLATE (no zlib header -- Inflater(nowrap = true) is what makes
 * that work; the default Inflater expects a zlib header and silently
 * fails on a bare deflate stream). Deliberately does not validate a
 * signature on the AuthnRequest itself -- Google Workspace (this
 * integration's actual target) doesn't sign its AuthnRequests, and the
 * ACS URL used is always the one *we* have on file for this SP (see
 * SamlService), never anything the request itself supplies, so a forged
 * AuthnRequest can't redirect a signed assertion anywhere other than the
 * registered ACS URL.
 */
object SamlAuthnRequestParser {
    private val documentBuilderFactory = DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
        // XXE hardening -- this parses attacker-reachable input (anyone can
        // hit GET /saml/sso with an arbitrary SAMLRequest).
        setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        setFeature("http://xml.org/sax/features/external-general-entities", false)
        setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        isExpandEntityReferences = false
    }

    fun parse(samlRequestParam: String): ParsedAuthnRequest {
        val compressed = try {
            Base64.getDecoder().decode(samlRequestParam)
        } catch (ex: IllegalArgumentException) {
            throw InvalidSamlRequestException("SAMLRequest is not valid base64")
        }

        val xmlBytes = try {
            InflaterInputStream(ByteArrayInputStream(compressed), Inflater(true)).use { it.readBytes() }
        } catch (ex: Exception) {
            throw InvalidSamlRequestException("SAMLRequest could not be inflated")
        }

        val document = try {
            documentBuilderFactory.newDocumentBuilder().parse(ByteArrayInputStream(xmlBytes))
        } catch (ex: Exception) {
            throw InvalidSamlRequestException("SAMLRequest is not well-formed XML")
        }

        val root = document.documentElement
        if (root.localName != "AuthnRequest") {
            throw InvalidSamlRequestException("expected an AuthnRequest")
        }
        val id = root.getAttribute("ID").takeIf { it.isNotBlank() }
            ?: throw InvalidSamlRequestException("AuthnRequest missing ID")

        val issuerEl = findChild(root, "Issuer")
            ?: throw InvalidSamlRequestException("AuthnRequest missing Issuer")
        val issuer = issuerEl.textContent.trim()
        if (issuer.isBlank()) {
            throw InvalidSamlRequestException("AuthnRequest Issuer is empty")
        }

        return ParsedAuthnRequest(id, issuer)
    }

    private fun findChild(parent: Element, localName: String): Element? {
        val children = parent.childNodes
        for (i in 0 until children.length) {
            val node = children.item(i)
            if (node is Element && node.localName == localName) return node
        }
        return null
    }
}
