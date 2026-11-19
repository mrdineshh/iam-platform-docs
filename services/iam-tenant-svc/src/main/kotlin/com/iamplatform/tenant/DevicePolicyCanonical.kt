package com.iamplatform.tenant

import java.time.Instant
import java.util.UUID

/**
 * The exact byte string OpenBao's transit key signs for a device policy (Endpoint Device Trust spec
 * Sections 10.3, 15.3, 16). The Rust agent's `policy_verifier::canonical_policy_encoding` rebuilds this
 * same string from the JSON it receives and checks the signature over it, so the two must never drift:
 * both pin the same golden vector in their tests (see DevicePolicyCanonicalTest).
 *
 * Properties this format guarantees, each one a spec requirement:
 *  - **Tenant- and device-bound** (15.3): tenantId and deviceId are signed, so a policy issued to one
 *    device cannot be replayed to another device or tenant.
 *  - **Complete**: every field the agent acts on is covered, including the heartbeat/posture intervals
 *    and failure mode, which an earlier version of this format left unsigned.
 *  - **Versioned**: the leading format tag lets a future change be introduced without ambiguity.
 *  - **Deterministic**: applications are ordered by id (as text), and timestamps are whole epoch seconds.
 *
 * Field values never contain '|' ':' or ';' (UUIDs, integers, enum names), so no escaping is needed.
 */
object DevicePolicyCanonical {
    const val FORMAT = "iam-device-policy-v1"

    /**
     * The browser-controls block of a device policy is signed on its own, with the same transit key, over this string. It is
     * deliberately NOT part of [FORMAT]'s string: changing that would make every already-installed agent reject every policy.
     * Bound to the same tenant, device, policy id/version and validity window as the policy it travels with, so it cannot be
     * replayed to another device or kept after the policy expires. The agent rebuilds it in `policy_verifier.rs`
     * (`canonical_browser_controls_encoding`); both pin the same golden vector.
     */
    const val BROWSER_CONTROLS_FORMAT = "iam-browser-controls-v1"

    fun encodeBrowserControls(
        tenantId: UUID,
        deviceId: UUID,
        policyId: UUID,
        policyVersion: Int,
        issuedAt: Instant,
        expiresAt: Instant,
        blockPersonalMicrosoft: Boolean,
    ): String = listOf(
        BROWSER_CONTROLS_FORMAT, tenantId, deviceId, policyId, policyVersion, issuedAt.epochSecond, expiresAt.epochSecond, blockPersonalMicrosoft,
    ).joinToString("|")

    /** The order applications are both signed and returned in; callers must use this one ordering. */
    fun ordered(apps: List<DeviceAppPolicyResponse>): List<DeviceAppPolicyResponse> =
        apps.sortedBy { it.applicationId.toString() }

    fun encode(
        tenantId: UUID,
        deviceId: UUID,
        policyId: UUID,
        policyVersion: Int,
        issuedAt: Instant,
        expiresAt: Instant,
        deviceStatus: String,
        heartbeatIntervalSeconds: Int,
        postureIntervalSeconds: Int,
        agentFailureMode: String,
        apps: List<DeviceAppPolicyResponse>,
    ): String {
        val appsPart = ordered(apps).joinToString(";") {
            "${it.applicationId}:${it.pendingAccess}:${it.offlineAccess}:${it.offlineGraceSeconds}:${it.failureMode}"
        }
        return listOf(
            FORMAT, tenantId, deviceId, policyId, policyVersion, issuedAt.epochSecond, expiresAt.epochSecond,
            deviceStatus, heartbeatIntervalSeconds, postureIntervalSeconds, agentFailureMode, appsPart,
        ).joinToString("|")
    }
}
