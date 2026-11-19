package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

/**
 * The Rust agent pins the byte-for-byte identical GOLDEN string in
 * `agent-core/src/policy_verifier.rs` (`golden_vector_matches_the_backend`). If either side changes the
 * format, one of the two tests fails instead of every device silently rejecting every policy.
 */
class DevicePolicyCanonicalTest {

    private val tenant = UUID.fromString("11111111-1111-1111-1111-111111111111")
    private val device = UUID.fromString("22222222-2222-2222-2222-222222222222")
    private val policy = UUID.fromString("33333333-3333-3333-3333-333333333333")

    private val appA = DeviceAppPolicyResponse(UUID.fromString("44444444-4444-4444-4444-444444444444"), false, true, 86400, "FAIL_CLOSED")
    private val appB = DeviceAppPolicyResponse(UUID.fromString("00000000-0000-0000-0000-000000000009"), true, false, 0, "RISK_BASED")

    // java.util.UUID.compareTo treats the high bits as a SIGNED long, so this id sorts *before* appA as a
    // UUID but *after* it as text. The format sorts as text; this id is here to prove it.
    private val appC = DeviceAppPolicyResponse(UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff"), false, false, 0, "FAIL_OPEN")

    private fun encode(
        tenantId: UUID = tenant,
        deviceId: UUID = device,
        status: String = "APPROVED",
        heartbeat: Int = 300,
        mode: String = "RISK_BASED",
        apps: List<DeviceAppPolicyResponse> = listOf(appA, appB, appC),
    ) = DevicePolicyCanonical.encode(
        tenantId, deviceId, policy, 7, Instant.ofEpochSecond(1_800_000_000), Instant.ofEpochSecond(1_800_000_900),
        status, heartbeat, 900, mode, apps,
    )

    @Test
    fun `golden vector`() {
        assertEquals(
            "iam-device-policy-v1|11111111-1111-1111-1111-111111111111|22222222-2222-2222-2222-222222222222|" +
                "33333333-3333-3333-3333-333333333333|7|1800000000|1800000900|APPROVED|300|900|RISK_BASED|" +
                "00000000-0000-0000-0000-000000000009:true:false:0:RISK_BASED;" +
                "44444444-4444-4444-4444-444444444444:false:true:86400:FAIL_CLOSED;" +
                "ffffffff-ffff-ffff-ffff-ffffffffffff:false:false:0:FAIL_OPEN",
            encode(),
        )
    }

    @Test
    fun `browser controls golden vector`() {
        assertEquals(
            "iam-browser-controls-v1|11111111-1111-1111-1111-111111111111|22222222-2222-2222-2222-222222222222|" +
                "33333333-3333-3333-3333-333333333333|7|1800000000|1800000900|true",
            controls(),
        )
    }

    private fun controls(block: Boolean = true, deviceId: UUID = device, version: Int = 7, expires: Long = 1_800_000_900) =
        DevicePolicyCanonical.encodeBrowserControls(
            tenant, deviceId, policy, version, Instant.ofEpochSecond(1_800_000_000), Instant.ofEpochSecond(expires), block,
        )

    @Test
    fun `the browser controls string changes with the choice, the device, the policy version and the expiry`() {
        val base = controls()
        assertNotEquals(base, controls(block = false))
        assertNotEquals(base, controls(deviceId = UUID.randomUUID()))
        assertNotEquals(base, controls(version = 8))
        assertNotEquals(base, controls(expires = 1_800_000_901))
    }

    @Test
    fun `the browser controls string never equals a policy string, so one signature cannot stand in for the other`() {
        assertNotEquals(encode(), controls())
        assertEquals(true, controls().startsWith("iam-browser-controls-v1|") && encode().startsWith("iam-device-policy-v1|"))
    }

    @Test
    fun `an empty application list still encodes (trailing separator, no apps)`() {
        assertEquals(
            "iam-device-policy-v1|11111111-1111-1111-1111-111111111111|22222222-2222-2222-2222-222222222222|" +
                "33333333-3333-3333-3333-333333333333|7|1800000000|1800000900|APPROVED|300|900|RISK_BASED|",
            encode(apps = emptyList()),
        )
    }

    @Test
    fun `input order of applications does not change the signed string`() {
        assertEquals(encode(apps = listOf(appA, appB, appC)), encode(apps = listOf(appC, appB, appA)))
    }

    @Test
    fun `a policy for one device or tenant cannot be mistaken for another`() {
        val base = encode()
        assertNotEquals(base, encode(deviceId = UUID.fromString("99999999-9999-9999-9999-999999999999")))
        assertNotEquals(base, encode(tenantId = UUID.fromString("99999999-9999-9999-9999-999999999999")))
    }

    @Test
    fun `every field the agent acts on is covered by the signature`() {
        val base = encode()
        assertNotEquals(base, encode(status = "SUSPENDED"))
        assertNotEquals(base, encode(heartbeat = 3600))
        assertNotEquals(base, encode(mode = "FAIL_OPEN"))
        assertNotEquals(base, encode(apps = listOf(appA.copy(offlineGraceSeconds = 1), appB, appC)))
    }
}
