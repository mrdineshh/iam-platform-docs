package com.iamplatform.tenant

import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PostureEvaluatorTest {

    private fun signals(disk: String? = "ENABLED", av: String? = "ENABLED", fw: String? = "ENABLED") =
        PostureSignals(diskEncryption = disk, antivirus = av, firewall = fw)

    @Test
    fun `everything enabled is compliant with no risk and no reasons`() {
        val result = PostureEvaluator.evaluate(signals())
        assertEquals(PostureStatus.COMPLIANT, result.status)
        assertEquals(0, result.riskScore)
        assertTrue(result.reasons.isEmpty())
    }

    @Test
    fun `any required check being off makes the device non-compliant and says which`() {
        assertEquals(listOf("Disk encryption (BitLocker) is off"), PostureEvaluator.evaluate(signals(disk = "DISABLED")).reasons)
        assertEquals(listOf("Antivirus real-time protection is off"), PostureEvaluator.evaluate(signals(av = "DISABLED")).reasons)
        assertEquals(listOf("Firewall is off"), PostureEvaluator.evaluate(signals(fw = "DISABLED")).reasons)
        listOf(signals(disk = "DISABLED"), signals(av = "DISABLED"), signals(fw = "DISABLED")).forEach {
            assertEquals(PostureStatus.NON_COMPLIANT, PostureEvaluator.evaluate(it).status)
        }
    }

    @Test
    fun `a check that could not be determined is never a pass, but is not a failure either`() {
        val result = PostureEvaluator.evaluate(signals(disk = "UNKNOWN"))
        assertEquals(PostureStatus.UNKNOWN, result.status)
        assertEquals(listOf("Disk encryption (BitLocker) could not be determined"), result.reasons)
        // Missing entirely (an older agent that does not report it) is the same as unknown.
        assertEquals(PostureStatus.UNKNOWN, PostureEvaluator.evaluate(signals(av = null)).status)
    }

    @Test
    fun `a definite failure outranks an unknown check`() {
        assertEquals(PostureStatus.NON_COMPLIANT, PostureEvaluator.evaluate(signals(disk = "DISABLED", av = "UNKNOWN")).status)
    }

    @Test
    fun `unrecognised or oddly-cased values are tolerated, never an error`() {
        assertEquals(PostureStatus.COMPLIANT, PostureEvaluator.evaluate(signals(disk = " enabled ", av = "Enabled", fw = "ENABLED")).status)
        assertEquals(PostureStatus.UNKNOWN, PostureEvaluator.evaluate(signals(disk = "SOMETHING_NEW")).status)
        assertEquals(PostureStatus.UNKNOWN, PostureEvaluator.evaluate(PostureSignals()).status) // nothing reported at all
    }

    @Test
    fun `risk is 40 per failed check and 10 per unknown one, capped at 100`() {
        assertEquals(40, PostureEvaluator.evaluate(signals(disk = "DISABLED")).riskScore)
        assertEquals(10, PostureEvaluator.evaluate(signals(disk = "UNKNOWN")).riskScore)
        assertEquals(90, PostureEvaluator.evaluate(signals(disk = "DISABLED", av = "DISABLED", fw = "UNKNOWN")).riskScore)
        assertEquals(100, PostureEvaluator.evaluate(signals(disk = "DISABLED", av = "DISABLED", fw = "DISABLED")).riskScore)
    }

    @Test
    fun `TPM, secure boot and patch date are informational and never affect compliance`() {
        val result = PostureEvaluator.evaluate(signals().copy(tpmPresent = "DISABLED", secureBoot = "DISABLED", lastHotfixDate = "2001-01-01"))
        assertEquals(PostureStatus.COMPLIANT, result.status)
    }
}
