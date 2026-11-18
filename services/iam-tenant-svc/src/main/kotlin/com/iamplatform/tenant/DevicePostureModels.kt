package com.iamplatform.tenant

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import jakarta.validation.constraints.Size

/**
 * The raw facts an endpoint agent reports about its device (Endpoint Device Trust spec Sections 4.1, 13.3 and
 * BRD FR-5.4). The agent reports *facts only*; whether those facts are acceptable is decided here, on the
 * server ([PostureEvaluator]), so a compromised or modified agent cannot simply claim "compliant".
 *
 * Fields are plain strings, deliberately: a newer agent that reports a value this server does not know must
 * degrade to "could not be determined", not be rejected with a 400 and lose the rest of the report.
 * Tri-state values are "ENABLED", "DISABLED" or anything else (treated as unknown).
 */
@JsonIgnoreProperties(ignoreUnknown = true)
data class PostureSignals(
    @field:Size(max = 255) val osName: String? = null,
    @field:Size(max = 64) val osVersion: String? = null,
    @field:Size(max = 64) val osBuild: String? = null,
    @field:Size(max = 16) val diskEncryption: String? = null,
    @field:Size(max = 16) val antivirus: String? = null,
    @field:Size(max = 255) val antivirusProduct: String? = null,
    @field:Size(max = 16) val firewall: String? = null,
    /** ENABLED means a TPM is present. Informational: not a compliance requirement in the default rules. */
    @field:Size(max = 16) val tpmPresent: String? = null,
    @field:Size(max = 16) val secureBoot: String? = null,
    @field:Size(max = 32) val lastHotfixDate: String? = null,
    /** Epoch seconds on the agent's clock when the facts were gathered. */
    val collectedAt: Long? = null,
)

data class PostureEvaluation(
    val status: PostureStatus,
    /** 0 (nothing wrong) to 100. Shown to admins; not used to gate anything yet. */
    val riskScore: Int,
    /** Human-readable, one per failed or undeterminable required check. Empty when compliant. */
    val reasons: List<String>,
)

/**
 * The default compliance rules (BRD FR-5.4; PDF Section 13.3 lets a tenant configure these later -- until
 * then every tenant gets this fixed set):
 *
 *  - Disk encryption, antivirus real-time protection and the firewall must all be ENABLED.
 *  - Any of them DISABLED  -> NON_COMPLIANT.
 *  - None disabled, but any could not be determined -> UNKNOWN. An unreadable check is never treated as a
 *    pass (graceful degradation toward the safer reading, ENGINEERING_GUARDRAILS section 2), but it is not
 *    a failure either: the agent may simply lack permission, or the machine may be a Server SKU.
 *  - Everything ENABLED -> COMPLIANT.
 *
 * Risk score: 40 per disabled required check, 10 per undeterminable one, capped at 100.
 */
object PostureEvaluator {
    private const val DISABLED_WEIGHT = 40
    private const val UNKNOWN_WEIGHT = 10

    fun evaluate(signals: PostureSignals): PostureEvaluation {
        val required = listOf(
            "Disk encryption (BitLocker)" to signals.diskEncryption,
            "Antivirus real-time protection" to signals.antivirus,
            "Firewall" to signals.firewall,
        )
        var disabled = 0
        var unknown = 0
        val reasons = mutableListOf<String>()
        for ((name, value) in required) {
            when (value?.trim()?.uppercase()) {
                "ENABLED" -> Unit
                "DISABLED" -> { disabled++; reasons += "$name is off" }
                else -> { unknown++; reasons += "$name could not be determined" }
            }
        }
        val status = when {
            disabled > 0 -> PostureStatus.NON_COMPLIANT
            unknown > 0 -> PostureStatus.UNKNOWN
            else -> PostureStatus.COMPLIANT
        }
        return PostureEvaluation(status, minOf(100, disabled * DISABLED_WEIGHT + unknown * UNKNOWN_WEIGHT), reasons)
    }
}
