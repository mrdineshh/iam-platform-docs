//! `iam-endpoint-agent --status`: a read-only, human-readable summary of what this agent knows and what it
//! would do, built from local files only (no network). Shows enrollment, the signed policy in force, how
//! fresh it is, the offline behaviour (fail-closed / fail-open / risk-based and grace, spec 15.2) and what the
//! local decision is right now. Never prints key material or tokens.

use crate::config::AgentConfig;
use crate::policy_state::{FailureMode, LocalDecision, PolicyCache};
use crate::secure_storage::StoredState;

fn age(secs: i64) -> String {
    let secs = secs.max(0);
    match secs {
        0..=89 => format!("{secs} s"),
        90..=5399 => format!("{} min", secs / 60),
        5400..=172_799 => format!("{:.1} h", secs as f64 / 3600.0),
        _ => format!("{} days", secs / 86_400),
    }
}

fn mode_text(raw: &str) -> &'static str {
    match FailureMode::parse(raw) {
        FailureMode::FailClosed => "fail-closed (deny when the policy cannot be refreshed)",
        FailureMode::FailOpen => "fail-open (allow only within each app's grace period)",
        FailureMode::RiskBased => "risk-based (allow only where offline access is enabled, within its grace period)",
    }
}

pub fn render_status(state: Option<&StoredState>, cache: Option<&PolicyCache>, config: &AgentConfig, now: i64) -> String {
    let mut out = String::new();
    let mut line = |label: &str, value: String| out.push_str(&format!("{label:<22}{value}\n"));

    line("Platform", config.backend_base_url.clone());
    line("Tenant", config.tenant_id.clone());
    line(
        "Auto-update",
        if config.release_public_key_base64.as_deref().is_some_and(|k| !k.trim().is_empty()) { "on (signed releases only)".to_string() } else { "off (no release key configured)".to_string() },
    );

    let device_id = state.and_then(|s| s.device_id);
    match (state, device_id) {
        (Some(s), Some(id)) => {
            line("Enrollment", format!("enrolled, device {id}"));
            let protection = match s.key_assurance_level {
                crate::key_provider::KeyAssuranceLevel::HardwareTpm => "TPM hardware",
                crate::key_provider::KeyAssuranceLevel::HardwareCng => "CNG hardware",
                crate::key_provider::KeyAssuranceLevel::Software => "software",
            };
            line("Device key", format!("{} ({protection} protection)", s.key_algorithm));
        }
        _ => {
            line("Enrollment", "NOT enrolled -- run:  iam-endpoint-agent --enroll".to_string());
            return out;
        }
    }

    let Some(accepted) = cache.and_then(|c| c.accepted.as_ref()) else {
        line("Policy", "none received yet (the agent has not completed a sync)".to_string());
        line("Local decision", "DENY (no policy)".to_string());
        return out;
    };
    let policy = &accepted.policy;
    line("Device status", policy.device_status.clone());
    line("Policy", format!("version {}, last refreshed {} ago", policy.policy_version, age(now - accepted.accepted_at)));
    let remaining = accepted.expires_at - now;
    line(
        "Policy validity",
        if remaining >= 0 { format!("valid for another {}", age(remaining)) } else { format!("EXPIRED {} ago", age(-remaining)) },
    );
    line("Sync intervals", format!("heartbeat {} s, posture {} s", policy.heartbeat_interval_seconds, policy.posture_interval_seconds));
    line("When offline", mode_text(&policy.agent_failure_mode).to_string());
    for app in &policy.applications {
        line(
            "  app",
            format!(
                "{}  mode={}  offline_access={}  grace={}  pending_device_access={}",
                app.application_id,
                app.failure_mode,
                app.offline_access,
                if app.offline_grace_seconds > 0 { age(app.offline_grace_seconds) } else { "none".to_string() },
                app.pending_access
            ),
        );
    }
    let decision = match cache.map(|c| c.decide(None, now)) {
        Some(LocalDecision::Allow) => "ALLOW".to_string(),
        Some(LocalDecision::Deny(reason)) => format!("DENY ({reason:?})"),
        None => "DENY (no policy)".to_string(),
    };
    line("Local decision now", decision);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_state::PolicyCache;
    use crate::policy_verifier::test_support::{app, Fixture, DEVICE};
    use crate::secure_storage::test_state;

    const T0: i64 = 1_800_000_000;

    fn config() -> AgentConfig {
        serde_json::from_value(serde_json::json!({
            "backend_base_url": "https://iam.example.com",
            "enrollment_login_url": "https://login.example.com/device-enroll",
            "tenant_id": "11111111-1111-4111-8111-111111111111",
            "device_policy_public_key_base64": "AAAA"
        }))
        .unwrap()
    }

    fn cache(status: &str, apps: Vec<crate::api_client::DeviceAppPolicy>) -> PolicyCache {
        let f = Fixture::new();
        let verified = f.verified(4, T0, 900, status, apps);
        let mut c = PolicyCache::default();
        c.accept(verified, T0 + 5).unwrap();
        c
    }

    #[test]
    fn age_is_readable() {
        assert_eq!(age(30), "30 s");
        assert_eq!(age(600), "10 min");
        assert_eq!(age(7200), "2.0 h");
        assert_eq!(age(3 * 86_400), "3 days");
    }

    #[test]
    fn not_enrolled_says_how_to_enroll() {
        let text = render_status(None, None, &config(), T0);
        assert!(text.contains("NOT enrolled"));
        assert!(text.contains("--enroll"));
    }

    #[test]
    fn a_healthy_device_shows_policy_and_an_allow_decision() {
        let state = test_state(DEVICE.parse().unwrap());
        let text = render_status(Some(&state), Some(&cache("APPROVED", vec![])), &config(), T0 + 60);
        assert!(text.contains("APPROVED"), "{text}");
        assert!(text.contains("version 4"), "{text}");
        assert!(text.contains("Local decision now    ALLOW"), "{text}");
    }

    #[test]
    fn a_pending_device_is_denied_and_the_reason_is_shown() {
        let state = test_state(DEVICE.parse().unwrap());
        let text = render_status(Some(&state), Some(&cache("PENDING_APPROVAL", vec![])), &config(), T0 + 60);
        assert!(text.contains("DENY (DeviceNotApproved"), "{text}");
    }

    #[test]
    fn an_expired_policy_with_no_grace_is_denied_offline() {
        let state = test_state(DEVICE.parse().unwrap());
        let later = T0 + 900 + 3600;
        let text = render_status(Some(&state), Some(&cache("APPROVED", vec![app("a1111111-1111-4111-8111-111111111111", false, false, 0, "FAIL_CLOSED")])), &config(), later);
        assert!(text.contains("EXPIRED"), "{text}");
        assert!(text.contains("DENY (PolicyExpired)") || text.contains("DENY (OfflineGraceExceeded)"), "{text}");
    }

    #[test]
    fn the_output_never_contains_key_material() {
        let state = test_state(DEVICE.parse().unwrap());
        let text = render_status(Some(&state), Some(&cache("APPROVED", vec![])), &config(), T0 + 60);
        let material = serde_json::to_value(state.key_material.as_ref().unwrap()).unwrap();
        let bytes: Vec<u8> = material["signing_key_bytes"].as_array().unwrap().iter().map(|n| n.as_u64().unwrap() as u8).collect();
        assert_eq!(bytes.len(), 32);
        use base64::{engine::general_purpose::STANDARD, Engine};
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert!(!text.contains(&STANDARD.encode(&bytes)) && !text.contains(&hex) && !text.contains("signing_key"), "{text}");
    }
}
