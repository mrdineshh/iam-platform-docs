//! The agent's local view of its signed device policy, and the rules for what that policy still permits
//! when it can no longer be refreshed -- Endpoint Device Trust spec Section 15 (agent health, failure modes,
//! offline policy) and Appendix A (defaults).
//!
//! Pure logic: no clock reads, no I/O, no network. Every function takes `now` as an argument, so every rule
//! below is covered by a deterministic unit test, including the negative paths.
//!
//! Scope of these decisions: they govern controls enforced **locally by the agent** (for example the
//! browser sign-in policy). They are not access decisions for SaaS apps -- those are made server-side by
//! the PEP (spec Section 6.4: "not merely by the local agent"), which has its own heartbeat-freshness view.

use crate::policy_verifier::VerifiedPolicy;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Tolerated difference between this machine's clock and the issuing server's, for expiry checks and for
/// deciding that the clock went backwards. Small enough to not meaningfully extend a policy's life.
pub const CLOCK_SKEW_SECONDS: i64 = 120;

/// Spec Section 15.2. Anything unrecognised is treated as the strictest mode, never the loosest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    FailClosed,
    FailOpen,
    RiskBased,
}

impl FailureMode {
    pub fn parse(raw: &str) -> Self {
        match raw {
            "FAIL_OPEN" => FailureMode::FailOpen,
            "RISK_BASED" => FailureMode::RiskBased,
            _ => FailureMode::FailClosed,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    NoPolicy,
    ClockMovedBackwards,
    DeviceNotApproved(String),
    PolicyExpired,
    OfflineGraceExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalDecision {
    Allow,
    Deny(DenyReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// The issue time is older than a policy already accepted (replay of an older, validly signed policy).
    OlderThanAccepted,
    /// The version is lower than a policy already accepted (rollback to an older rule set).
    VersionRolledBack,
    /// Signed correctly but already past its expiry (a captured policy replayed later).
    AlreadyExpired,
    /// This machine's clock is behind the highest time it has ever observed.
    ClockMovedBackwards,
}

/// A verified policy plus the local bookkeeping needed for offline decisions. `accepted_at` is when *this
/// agent* last obtained it from the backend; offline grace is measured from there, not from `issued_at`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcceptedPolicy {
    pub policy: crate::api_client::DevicePolicyResponse,
    pub issued_at: i64,
    pub expires_at: i64,
    pub accepted_at: i64,
}

/// Persisted between runs (see secure_storage). `clock_high_water` is the largest wall-clock time this agent
/// has ever observed: a later reading that is meaningfully smaller means the clock was set back, which would
/// otherwise let an expired policy or an exhausted grace period look valid again.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyCache {
    pub accepted: Option<AcceptedPolicy>,
    pub clock_high_water: i64,
}

impl PolicyCache {
    /// Records the current time. Returns `false` if the clock is behind what this agent has already seen.
    pub fn observe_clock(&mut self, now: i64) -> bool {
        if now + CLOCK_SKEW_SECONDS < self.clock_high_water {
            return false;
        }
        self.clock_high_water = self.clock_high_water.max(now);
        true
    }

    /// Takes a policy into the cache only if it is not a replay, a rollback, or already expired. Accepting
    /// the *same* policy again (equal version and issue time) is the normal periodic refresh.
    pub fn accept(&mut self, verified: VerifiedPolicy, now: i64) -> Result<(), RejectReason> {
        if !self.observe_clock(now) {
            return Err(RejectReason::ClockMovedBackwards);
        }
        if now > verified.expires_at() + CLOCK_SKEW_SECONDS {
            return Err(RejectReason::AlreadyExpired);
        }
        if let Some(current) = &self.accepted {
            if verified.policy().policy_version < current.policy.policy_version {
                return Err(RejectReason::VersionRolledBack);
            }
            if verified.issued_at() < current.issued_at {
                return Err(RejectReason::OlderThanAccepted);
            }
        }
        let (issued_at, expires_at) = (verified.issued_at(), verified.expires_at());
        self.accepted = Some(AcceptedPolicy { policy: verified.into_policy(), issued_at, expires_at, accepted_at: now });
        Ok(())
    }

    pub fn policy_version(&self) -> i32 {
        self.accepted.as_ref().map_or(0, |a| a.policy.policy_version)
    }

    /// True while the cached policy is within its signed lifetime (so a refresh is not overdue).
    pub fn is_fresh(&self, now: i64) -> bool {
        self.accepted.as_ref().is_some_and(|a| now <= a.expires_at + CLOCK_SKEW_SECONDS)
    }

    /// What a locally enforced control may do right now. `app` is the application the control relates to,
    /// or `None` for a device-wide control that belongs to no particular app.
    ///
    /// Order matters and is deliberate: no policy, then clock tampering, then device state, then expiry.
    pub fn decide(&self, app: Option<Uuid>, now: i64) -> LocalDecision {
        let Some(accepted) = &self.accepted else {
            return LocalDecision::Deny(DenyReason::NoPolicy);
        };
        if now + CLOCK_SKEW_SECONDS < self.clock_high_water {
            return LocalDecision::Deny(DenyReason::ClockMovedBackwards);
        }

        let policy = &accepted.policy;
        let app_rule = app.and_then(|id| policy.applications.iter().find(|a| a.application_id == id));

        // Device state gate (spec Section 6.2): APPROVED passes; a pending device passes only for apps the
        // admin explicitly opened to pending devices (Section 6.4); everything else is denied.
        match policy.device_status.as_str() {
            "APPROVED" => {}
            "PENDING_APPROVAL" if app_rule.is_some_and(|a| a.pending_access) => {}
            other => return LocalDecision::Deny(DenyReason::DeviceNotApproved(other.to_string())),
        }

        if now <= accepted.expires_at + CLOCK_SKEW_SECONDS {
            return LocalDecision::Allow;
        }

        // The policy lapsed and could not be refreshed: the configured failure mode decides (Section 15.2).
        // A per-application mode overrides the device-wide one.
        let mode = FailureMode::parse(app_rule.map_or(policy.agent_failure_mode.as_str(), |a| a.failure_mode.as_str()));
        let (offline_access, grace) = app_rule.map_or((false, 0), |a| (a.offline_access, a.offline_grace_seconds));
        let within_grace = grace > 0 && now <= accepted.accepted_at + grace;

        match mode {
            FailureMode::FailClosed => LocalDecision::Deny(DenyReason::PolicyExpired),
            // "Allow ... for a limited period. Only where explicitly approved": the admin chose this mode for
            // the app, and the period is its grace window. No window configured means no period at all.
            FailureMode::FailOpen if within_grace => LocalDecision::Allow,
            // "Evaluate per-application risk and grace rules": offline access must also be explicitly enabled.
            FailureMode::RiskBased if offline_access && within_grace => LocalDecision::Allow,
            _ => LocalDecision::Deny(DenyReason::OfflineGraceExceeded),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_verifier::test_support::{app, Fixture};

    const APP: &str = "44444444-4444-4444-4444-444444444444";
    const OTHER_APP: &str = "55555555-5555-5555-5555-555555555555";
    const T0: i64 = 1_800_000_000;

    fn app_id() -> Uuid {
        APP.parse().unwrap()
    }

    fn cache_with(f: &Fixture, version: i32, issued_at: i64, status: &str, apps: Vec<crate::api_client::DeviceAppPolicy>, accepted_at: i64) -> PolicyCache {
        let mut cache = PolicyCache::default();
        cache.accept(f.verified(version, issued_at, 900, status, apps), accepted_at).unwrap();
        cache
    }

    // ---- accepting policies: replay, rollback, expiry, clock ----

    #[test]
    fn a_fresh_policy_is_accepted_and_remembered() {
        let f = Fixture::new();
        let cache = cache_with(&f, 3, T0, "APPROVED", vec![], T0);
        assert_eq!(cache.policy_version(), 3);
        assert!(cache.is_fresh(T0 + 100));
    }

    #[test]
    fn refreshing_with_an_identical_policy_is_accepted() {
        let f = Fixture::new();
        let mut cache = cache_with(&f, 3, T0, "APPROVED", vec![], T0);
        assert!(cache.accept(f.verified(3, T0, 900, "APPROVED", vec![]), T0 + 300).is_ok());
        assert_eq!(cache.accepted.as_ref().unwrap().accepted_at, T0 + 300);
    }

    #[test]
    fn a_lower_version_is_rejected_as_a_rollback() {
        let f = Fixture::new();
        let mut cache = cache_with(&f, 5, T0, "APPROVED", vec![], T0);
        assert_eq!(cache.accept(f.verified(4, T0 + 10, 900, "APPROVED", vec![]), T0 + 10), Err(RejectReason::VersionRolledBack));
        assert_eq!(cache.policy_version(), 5);
    }

    #[test]
    fn an_older_issue_time_is_rejected_as_a_replay_even_with_a_valid_signature() {
        // e.g. a captured "APPROVED" policy replayed after the device was suspended.
        let f = Fixture::new();
        let mut cache = cache_with(&f, 3, T0 + 500, "SUSPENDED", vec![], T0 + 500);
        assert_eq!(cache.accept(f.verified(3, T0, 900, "APPROVED", vec![]), T0 + 510), Err(RejectReason::OlderThanAccepted));
        assert_eq!(cache.accepted.as_ref().unwrap().policy.device_status, "SUSPENDED");
    }

    #[test]
    fn an_already_expired_policy_is_rejected() {
        let f = Fixture::new();
        let mut cache = PolicyCache::default();
        let stale = f.verified(3, T0, 900, "APPROVED", vec![]);
        assert_eq!(cache.accept(stale, T0 + 900 + CLOCK_SKEW_SECONDS + 1), Err(RejectReason::AlreadyExpired));
        assert!(cache.accepted.is_none());
    }

    #[test]
    fn a_policy_just_inside_the_skew_allowance_is_accepted() {
        let f = Fixture::new();
        let mut cache = PolicyCache::default();
        assert!(cache.accept(f.verified(3, T0, 900, "APPROVED", vec![]), T0 + 900 + CLOCK_SKEW_SECONDS).is_ok());
    }

    #[test]
    fn nothing_is_accepted_once_the_clock_has_gone_backwards() {
        let f = Fixture::new();
        let mut cache = cache_with(&f, 3, T0, "APPROVED", vec![], T0);
        cache.observe_clock(T0 + 10_000);
        assert_eq!(cache.accept(f.verified(4, T0 + 20, 900, "APPROVED", vec![]), T0 + 20), Err(RejectReason::ClockMovedBackwards));
    }

    // ---- local decisions ----

    #[test]
    fn with_no_policy_everything_is_denied() {
        assert_eq!(PolicyCache::default().decide(None, T0), LocalDecision::Deny(DenyReason::NoPolicy));
    }

    #[test]
    fn an_approved_device_with_a_fresh_policy_is_allowed() {
        let f = Fixture::new();
        let cache = cache_with(&f, 1, T0, "APPROVED", vec![], T0);
        assert_eq!(cache.decide(None, T0 + 60), LocalDecision::Allow);
        assert_eq!(cache.decide(Some(app_id()), T0 + 60), LocalDecision::Allow);
    }

    #[test]
    fn a_suspended_revoked_or_non_compliant_device_is_denied_even_with_a_fresh_policy() {
        let f = Fixture::new();
        for status in ["SUSPENDED", "REVOKED", "NON_COMPLIANT", "REJECTED"] {
            let cache = cache_with(&f, 1, T0, status, vec![app(APP, true, true, 86_400, "FAIL_OPEN")], T0);
            assert_eq!(cache.decide(Some(app_id()), T0 + 1), LocalDecision::Deny(DenyReason::DeviceNotApproved(status.into())), "{status}");
        }
    }

    #[test]
    fn a_pending_device_is_allowed_only_for_apps_opened_to_pending_devices() {
        // Spec Section 6.4: HR allowed, Finance blocked.
        let f = Fixture::new();
        let cache = cache_with(&f, 1, T0, "PENDING_APPROVAL", vec![app(APP, true, false, 0, "FAIL_CLOSED"), app(OTHER_APP, false, false, 0, "FAIL_CLOSED")], T0);
        assert_eq!(cache.decide(Some(app_id()), T0 + 1), LocalDecision::Allow);
        assert_eq!(cache.decide(Some(OTHER_APP.parse().unwrap()), T0 + 1), LocalDecision::Deny(DenyReason::DeviceNotApproved("PENDING_APPROVAL".into())));
        assert_eq!(cache.decide(None, T0 + 1), LocalDecision::Deny(DenyReason::DeviceNotApproved("PENDING_APPROVAL".into())));
    }

    #[test]
    fn fail_closed_denies_as_soon_as_the_policy_lapses() {
        let f = Fixture::new();
        let cache = cache_with(&f, 1, T0, "APPROVED", vec![app(APP, false, true, 86_400, "FAIL_CLOSED")], T0);
        let lapsed = T0 + 900 + CLOCK_SKEW_SECONDS + 1;
        assert_eq!(cache.decide(Some(app_id()), lapsed), LocalDecision::Deny(DenyReason::PolicyExpired));
    }

    #[test]
    fn risk_based_allows_only_with_offline_access_enabled_and_within_grace() {
        let f = Fixture::new();
        let lapsed = T0 + 900 + CLOCK_SKEW_SECONDS + 1;

        let allowed = cache_with(&f, 1, T0, "APPROVED", vec![app(APP, false, true, 86_400, "RISK_BASED")], T0);
        assert_eq!(allowed.decide(Some(app_id()), lapsed), LocalDecision::Allow);
        assert_eq!(allowed.decide(Some(app_id()), T0 + 86_400), LocalDecision::Allow); // last second of grace
        assert_eq!(allowed.decide(Some(app_id()), T0 + 86_401), LocalDecision::Deny(DenyReason::OfflineGraceExceeded));

        let no_offline_access = cache_with(&f, 1, T0, "APPROVED", vec![app(APP, false, false, 86_400, "RISK_BASED")], T0);
        assert_eq!(no_offline_access.decide(Some(app_id()), lapsed), LocalDecision::Deny(DenyReason::OfflineGraceExceeded));

        let zero_grace = cache_with(&f, 1, T0, "APPROVED", vec![app(APP, false, true, 0, "RISK_BASED")], T0);
        assert_eq!(zero_grace.decide(Some(app_id()), lapsed), LocalDecision::Deny(DenyReason::OfflineGraceExceeded));
    }

    #[test]
    fn fail_open_allows_only_for_the_configured_grace_period_not_forever() {
        let f = Fixture::new();
        let lapsed = T0 + 900 + CLOCK_SKEW_SECONDS + 1;
        let cache = cache_with(&f, 1, T0, "APPROVED", vec![app(APP, false, false, 3_600, "FAIL_OPEN")], T0);
        assert_eq!(cache.decide(Some(app_id()), lapsed), LocalDecision::Allow);
        assert_eq!(cache.decide(Some(app_id()), T0 + 3_601), LocalDecision::Deny(DenyReason::OfflineGraceExceeded));

        let no_period = cache_with(&f, 1, T0, "APPROVED", vec![app(APP, false, false, 0, "FAIL_OPEN")], T0);
        assert_eq!(no_period.decide(Some(app_id()), lapsed), LocalDecision::Deny(DenyReason::OfflineGraceExceeded));
    }

    #[test]
    fn grace_is_measured_from_the_last_successful_sync_not_from_the_policy_issue_time() {
        let f = Fixture::new();
        // Issued at T0 but only obtained by this agent 600s later (e.g. it had been offline).
        let cache = cache_with(&f, 1, T0, "APPROVED", vec![app(APP, false, true, 1_000, "RISK_BASED")], T0 + 600);
        assert_eq!(cache.decide(Some(app_id()), T0 + 1_600), LocalDecision::Allow);
        assert_eq!(cache.decide(Some(app_id()), T0 + 1_601), LocalDecision::Deny(DenyReason::OfflineGraceExceeded));
    }

    #[test]
    fn a_device_wide_decision_uses_the_agent_failure_mode_and_has_no_per_app_grace() {
        // unsigned_policy's device-wide mode is RISK_BASED; with no app rule there is no grace to apply.
        let f = Fixture::new();
        let cache = cache_with(&f, 1, T0, "APPROVED", vec![], T0);
        assert_eq!(cache.decide(None, T0 + 60), LocalDecision::Allow);
        assert_eq!(cache.decide(None, T0 + 900 + CLOCK_SKEW_SECONDS + 1), LocalDecision::Deny(DenyReason::OfflineGraceExceeded));
    }

    #[test]
    fn an_unrecognised_failure_mode_fails_closed() {
        assert_eq!(FailureMode::parse("SOMETHING_NEW"), FailureMode::FailClosed);
        assert_eq!(FailureMode::parse(""), FailureMode::FailClosed);
        let f = Fixture::new();
        let cache = cache_with(&f, 1, T0, "APPROVED", vec![app(APP, false, true, 86_400, "SOMETHING_NEW")], T0);
        assert_eq!(cache.decide(Some(app_id()), T0 + 5_000), LocalDecision::Deny(DenyReason::PolicyExpired));
    }

    #[test]
    fn setting_the_clock_back_does_not_revive_an_expired_policy() {
        let f = Fixture::new();
        let mut cache = cache_with(&f, 1, T0, "APPROVED", vec![app(APP, false, true, 86_400, "RISK_BASED")], T0);
        // Time legitimately advances well past the policy's life and its grace period...
        cache.observe_clock(T0 + 200_000);
        assert_eq!(cache.decide(Some(app_id()), T0 + 200_000), LocalDecision::Deny(DenyReason::OfflineGraceExceeded));
        // ...then someone rolls the clock back to when the policy looked valid and the grace unspent.
        assert_eq!(cache.decide(Some(app_id()), T0 + 60), LocalDecision::Deny(DenyReason::ClockMovedBackwards));
    }

    #[test]
    fn ordinary_clock_jitter_within_the_skew_is_not_treated_as_tampering() {
        let f = Fixture::new();
        let mut cache = cache_with(&f, 1, T0, "APPROVED", vec![], T0);
        assert!(cache.observe_clock(T0 + 1_000));
        assert!(cache.observe_clock(T0 + 1_000 - CLOCK_SKEW_SECONDS)); // NTP step back of up to the skew
        assert!(!cache.observe_clock(T0 + 1_000 - CLOCK_SKEW_SECONDS - 1));
    }

    #[test]
    fn the_cache_survives_a_serialization_round_trip_exactly() {
        let f = Fixture::new();
        let cache = cache_with(&f, 4, T0, "APPROVED", vec![app(APP, false, true, 600, "RISK_BASED")], T0 + 5);
        let restored: PolicyCache = serde_json::from_str(&serde_json::to_string(&cache).unwrap()).unwrap();
        assert_eq!(cache, restored);
    }
}
