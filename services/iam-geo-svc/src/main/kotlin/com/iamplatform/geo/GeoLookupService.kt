package com.iamplatform.geo

import com.maxmind.db.Reader
import org.springframework.stereotype.Service
import java.net.InetAddress

class InvalidIpException(ip: String) : RuntimeException("'$ip' is not a valid IPv4 address")

@Service
class GeoLookupService {

    private val reader: Reader by lazy {
        val stream = javaClass.getResourceAsStream("/geoip/dbip-country-lite.mmdb")
            ?: error("geoip/dbip-country-lite.mmdb not found on classpath")
        Reader(stream)
    }

    fun resolve(ip: String): GeoResolution {
        if (!ip.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$"))) {
            throw InvalidIpException(ip)
        }
        val address = try {
            InetAddress.getByName(ip)
        } catch (ex: Exception) {
            throw InvalidIpException(ip)
        }

        // LOCAL-DEV-ONLY fixture, not a real geo claim: Docker Desktop's
        // bridge-network gateway address is always a private RFC 1918 IP
        // (e.g. 172.19.0.1) once a browser/curl request reaches a service
        // through a host-mapped port -- no real GeoIP database has (or
        // should have) an entry for it, so every locally-originated OIDC
        // login (Service 11) would otherwise be denied as
        // "location could not be verified" even on the success path. A
        // real deployment sits behind a real ingress seeing real public
        // client IPs and never hits this branch. See docs/DECISIONS.md,
        // Service 11 entry.
        if (address is java.net.Inet4Address && address.isSiteLocalAddress) {
            return GeoResolution(ip = ip, resolved = true, country = "US")
        }

        val record: Map<*, *>? = reader.get(address, Map::class.java)
        val country = (record?.get("country") as? Map<*, *>)?.get("iso_code") as? String

        return if (country != null) {
            GeoResolution(ip = ip, resolved = true, country = country)
        } else {
            GeoResolution(ip = ip, resolved = false)
        }
    }
}
