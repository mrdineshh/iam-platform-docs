package com.iamplatform.tenant

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI

class InvalidProvisioningTargetException(message: String) : RuntimeException(message)

/**
 * Guards every server-side call to an address an admin typed in (SCIM
 * endpoints). Without this an admin could point a "provisioning endpoint" at
 * http://iam-identity-svc:8080 or the cloud metadata server (169.254.169.254)
 * and use this service to read internal data (server-side request forgery).
 *
 * Rules: https only; no credentials in the URL; and every address the host
 * resolves to must be a normal public address (not loopback, private,
 * link-local, carrier-grade NAT, unique-local, multicast or "any"). It is
 * checked when a connection is saved AND again on every call, so changing a
 * DNS record later does not slip an internal address through. The one
 * remaining gap is a record that changes between this check and the actual
 * connection (DNS rebinding); redirects are also refused by the client.
 *
 * `iam.provisioning.allow-private-targets` relaxes all of this for local
 * development and tests only; it must stay false in any real deployment.
 */
@Component
class OutboundUrlGuard(
    @Value("\${iam.provisioning.allow-private-targets:false}") private val allowPrivateTargets: Boolean,
) {
    fun validate(rawUrl: String): URI {
        val uri = try {
            URI(rawUrl.trim())
        } catch (ex: Exception) {
            throw InvalidProvisioningTargetException("That is not a valid URL.")
        }
        val scheme = uri.scheme?.lowercase()
        val host = uri.host
        if (scheme == null || host.isNullOrBlank()) {
            throw InvalidProvisioningTargetException("The URL must include a scheme and host, for example https://app.example.com/scim/v2.")
        }
        if (scheme != "https" && scheme != "http") {
            throw InvalidProvisioningTargetException("Only https:// URLs are allowed.")
        }
        if (allowPrivateTargets) return uri

        if (scheme != "https") {
            throw InvalidProvisioningTargetException("Only https:// URLs are allowed.")
        }
        if (uri.userInfo != null) {
            throw InvalidProvisioningTargetException("Credentials must not be part of the URL.")
        }
        val addresses = try {
            InetAddress.getAllByName(host.removePrefix("[").removeSuffix("]"))
        } catch (ex: Exception) {
            throw InvalidProvisioningTargetException("The host '$host' could not be resolved.")
        }
        if (addresses.any { isInternal(it) }) {
            throw InvalidProvisioningTargetException("That address points to a private or internal network, which is not allowed.")
        }
        return uri
    }

    private fun isInternal(address: InetAddress): Boolean {
        if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress ||
            address.isSiteLocalAddress || address.isMulticastAddress
        ) {
            return true
        }
        val b = address.address
        // Carrier-grade NAT 100.64.0.0/10
        if (b.size == 4 && (b[0].toInt() and 0xFF) == 100 && (b[1].toInt() and 0xC0) == 0x40) return true
        // IPv6 unique-local fc00::/7
        if (address is Inet6Address && (b[0].toInt() and 0xFE) == 0xFC) return true
        return false
    }
}
