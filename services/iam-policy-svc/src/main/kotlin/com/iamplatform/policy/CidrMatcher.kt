package com.iamplatform.policy

import java.net.InetAddress

/**
 * IPv4-only, matching this platform's existing convention (iam-geo-svc's
 * contract is IPv4-only too -- see docs/DECISIONS.md, Service 13 entry, on
 * the dual-stack IPv6-mapped-address bug that convention exists to avoid).
 */
object CidrMatcher {
    fun matches(ip: String, cidr: String): Boolean {
        val (rangeIp, prefixStr) = cidr.split("/", limit = 2).let {
            if (it.size == 2) it[0] to it[1] else it[0] to "32"
        }
        val prefix = prefixStr.toIntOrNull() ?: return false
        if (prefix !in 0..32) return false

        val ipBits = toInt(ip) ?: return false
        val rangeBits = toInt(rangeIp) ?: return false
        if (prefix == 0) return true

        val mask = -1 shl (32 - prefix)
        return (ipBits and mask) == (rangeBits and mask)
    }

    fun anyMatches(ip: String, cidrs: List<String>): Boolean = cidrs.any { matches(ip, it) }

    private fun toInt(ip: String): Int? =
        try {
            val addr = InetAddress.getByName(ip)
            val bytes = addr.address
            if (bytes.size != 4) return null
            ((bytes[0].toInt() and 0xFF) shl 24) or
                ((bytes[1].toInt() and 0xFF) shl 16) or
                ((bytes[2].toInt() and 0xFF) shl 8) or
                (bytes[3].toInt() and 0xFF)
        } catch (ex: Exception) {
            null
        }
}
