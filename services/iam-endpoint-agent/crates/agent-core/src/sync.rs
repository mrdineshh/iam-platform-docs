//! The agent's steady-state loop: obtain the signed policy, verify it, remember it, report health.
//! (Endpoint Device Trust spec Sections 10.3, 15, 16, Appendix A: heartbeat and policy sync every 300 s by
//! default, driven by the signed policy's own intervals; retries with backoff.)
//!
//! Structure, for testability: [`Backend`] is the port (the production adapter is `DeviceBackend` in
//! api_client.rs); [`SyncEngine::tick`] is one pass and takes `now` as an argument; [`SyncEngine::run`] is
//! the thin loop around it. So the interesting behavior -- rejecting a tampered, replayed or rolled-back
//! policy, health reporting, backoff -- is tested against a fake backend with no network and no real sleeping.

use crate::integrity::{FindingKind, IntegrityMonitor};
use crate::local_log::LocalEventSink;
use crate::api_client::{AgentEvent, ApiError, DevicePolicyResponse, HeartbeatRequest};
use crate::policy_state::{PolicyCache, RejectReason};
use crate::policy_verifier::{verify_policy, PolicyVerificationError};
use crate::posture::{PostureCollector, PostureSignals};
use crate::secure_storage::PolicyStore;
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::watch;
use uuid::Uuid;

/// Everything the engine needs from the network. Production: `DeviceBackend`. Tests: a fake.
pub trait Backend: Send + Sync {
    fn fetch_policy(&self) -> impl Future<Output = Result<DevicePolicyResponse, ApiError>> + Send;
    fn heartbeat(&self, request: &HeartbeatRequest) -> impl Future<Output = Result<(), ApiError>> + Send;
    fn post_event(&self, event: &AgentEvent) -> impl Future<Output = Result<(), ApiError>> + Send;
    fn report_posture(&self, signals: &PostureSignals) -> impl Future<Output = Result<(), ApiError>> + Send;
}

/// Guards against a buggy or hostile interval (0 would spin; a huge value would silence the device).
const MIN_INTERVAL: Duration = Duration::from_secs(30);
const MAX_INTERVAL: Duration = Duration::from_secs(3600);
/// Posture is slower-moving and costlier to gather than a heartbeat (spec Appendix A: 900 s by default).
const DEFAULT_POSTURE_INTERVAL_SECS: i64 = 900;
const MIN_POSTURE_INTERVAL_SECS: i64 = 60;
const MAX_POSTURE_INTERVAL_SECS: i64 = 86_400;

pub struct SyncConfig {
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub transit_public_key_base64: String,
    pub agent_version: String,
    /// Used until the first policy supplies the real interval (spec Appendix A: 300 s).
    pub default_interval: Duration,
    pub max_backoff: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TickOutcome {
    Synced,
    /// The backend could not be reached or answered with an error. Not a security event.
    SyncFailed,
    /// The backend answered, but with a policy this agent refused (bad signature, wrong device, replay,
    /// rollback, expired...). A security event: it is reported and the previous policy stays in force.
    PolicyRejected,
}

/// Exponential backoff with jitter (ENGINEERING_GUARDRAILS section 2: "exponential backoff with jitter,
/// capped"). Pure: `jitter` in [0, 1) is supplied by the caller, so the result is deterministic in tests.
pub fn backoff_delay(failures: u32, base: Duration, max: Duration, jitter: f64) -> Duration {
    let exponent = failures.min(16);
    let raw = base.saturating_mul(1u32 << exponent).min(max);
    // +/-10 %: enough to stop a fleet that lost the backend together from retrying in lockstep.
    let factor = 1.0 + (jitter.clamp(0.0, 1.0) * 2.0 - 1.0) * 0.1;
    raw.mul_f64(factor).min(max)
}

pub struct SyncEngine<B: Backend, C: PostureCollector> {
    backend: B,
    collector: C,
    store: PolicyStore,
    cache: PolicyCache,
    config: SyncConfig,
    consecutive_failures: u32,
    last_posture_at: Option<i64>,
    integrity: Option<IntegrityMonitor>,
    local_log: Option<std::sync::Arc<dyn LocalEventSink>>,
}

impl<B: Backend, C: PostureCollector> SyncEngine<B, C> {
    /// Restores the persisted cache, if any, so a restart (or an offline boot) keeps the last-known-good
    /// policy, its anti-rollback state, and the clock high-water mark.
    pub fn new(backend: B, collector: C, store: PolicyStore, config: SyncConfig) -> Result<Self, crate::secure_storage::StorageError> {
        let cache = store.load()?.unwrap_or_default();
        Ok(Self { backend, collector, store, cache, config, consecutive_failures: 0, last_posture_at: None, integrity: None, local_log: None })
    }

    /// Mirrors every event the agent raises to the device's own log (Windows Event Log on Windows).
    pub fn with_local_log(mut self, sink: std::sync::Arc<dyn LocalEventSink>) -> Self {
        self.local_log = Some(sink);
        self
    }

    /// Turns on tamper detection (P1-16): the monitor is checked on every tick.
    pub fn with_integrity(mut self, monitor: IntegrityMonitor) -> Self {
        for label in monitor.unprotected() {
            tracing::warn!(file = label, "integrity monitoring cannot read this file, so it is not protected");
        }
        self.integrity = Some(monitor);
        self
    }

    pub fn cache(&self) -> &PolicyCache {
        &self.cache
    }

    /// One pass: fetch -> verify -> accept -> persist -> heartbeat.
    pub async fn tick(&mut self, now: i64) -> TickOutcome {
        let clock_ok = self.cache.observe_clock(now);
        let mut outcome = TickOutcome::Synced;

        if !clock_ok {
            self.report("agent.clock_moved_backwards", "WARNING", "system clock is behind the latest time this agent has seen").await;
        }

        match self.backend.fetch_policy().await {
            Err(err) => {
                tracing::warn!(error = %err, "policy fetch failed");
                outcome = TickOutcome::SyncFailed;
            }
            Ok(raw) => match self.verify_and_accept(raw, now) {
                Ok(()) => {}
                Err(reason) => {
                    tracing::error!(%reason, "rejecting device policy");
                    self.report("agent.policy_rejected", "CRITICAL", &reason).await;
                    outcome = TickOutcome::PolicyRejected;
                }
            },
        }

        if let Err(err) = self.store.save(&self.cache) {
            // The in-memory state is still correct; the next tick retries the write.
            tracing::error!(error = %err, "could not persist policy cache");
        }

        let findings = self.integrity.as_mut().map(|m| m.check()).unwrap_or_default();
        for finding in findings {
            let (event, severity) = match finding.kind {
                FindingKind::Modified => ("agent.tamper_detected", "CRITICAL"),
                FindingKind::Deleted => ("agent.tamper_detected", "CRITICAL"),
                FindingKind::Restored => ("agent.tamper_cleared", "INFO"),
            };
            tracing::error!(file = %finding.label, kind = ?finding.kind, "agent integrity check");
            self.report(event, severity, &format!("{} {:?}", finding.label, finding.kind)).await;
        }
        let compromised = self.integrity.as_ref().is_some_and(|m| m.is_compromised());

        let health = if outcome != TickOutcome::PolicyRejected && self.cache.is_fresh(now) && !compromised { "HEALTHY" } else { "DEGRADED" };
        let heartbeat = HeartbeatRequest {
            agent_version: self.config.agent_version.clone(),
            policy_version: self.cache.policy_version(),
            health_status: health.to_string(),
        };
        if let Err(err) = self.backend.heartbeat(&heartbeat).await {
            tracing::warn!(error = %err, "heartbeat failed");
            if outcome == TickOutcome::Synced {
                outcome = TickOutcome::SyncFailed;
            }
        }

        // After the heartbeat, so a slow collection can never delay "I am alive". It does not affect the
        // outcome either: posture trouble is not a reason to back off from the backend.
        self.report_posture_if_due(now).await;
        outcome
    }

    fn posture_interval_secs(&self) -> i64 {
        self.cache
            .accepted
            .as_ref()
            .map_or(DEFAULT_POSTURE_INTERVAL_SECS, |a| i64::from(a.policy.posture_interval_seconds))
            .clamp(MIN_POSTURE_INTERVAL_SECS, MAX_POSTURE_INTERVAL_SECS)
    }

    async fn report_posture_if_due(&mut self, now: i64) {
        // `now < last` (clock set back) counts as due rather than waiting out a nonsensical interval.
        let due = self.last_posture_at.is_none_or(|last| now < last || now - last >= self.posture_interval_secs());
        if !due {
            return;
        }
        match self.collector.collect().await {
            Ok(mut signals) => {
                signals.collected_at = Some(now);
                match self.backend.report_posture(&signals).await {
                    Ok(()) => self.last_posture_at = Some(now),
                    // Not recorded as sent, so the next tick tries again.
                    Err(err) => tracing::warn!(error = %err, "posture report failed; will retry next tick"),
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, "posture collection failed");
                // Mark it attempted: a collector that keeps failing must not be re-run (several seconds of
                // PowerShell) on every tick -- it gets another try at the next interval.
                self.last_posture_at = Some(now);
                self.report("agent.posture_collection_failed", "WARNING", &err.to_string()).await;
            }
        }
    }

    fn verify_and_accept(&mut self, raw: DevicePolicyResponse, now: i64) -> Result<(), String> {
        let verified = verify_policy(raw, &self.config.transit_public_key_base64, self.config.tenant_id, self.config.device_id)
            .map_err(|e: PolicyVerificationError| e.to_string())?;
        self.cache.accept(verified, now).map_err(|r: RejectReason| format!("{r:?}"))
    }

    /// Best-effort security event; failing to deliver it must never break the loop.
    async fn report(&self, event_type: &str, severity: &str, reason: &str) {
        if let Some(sink) = &self.local_log {
            sink.write(severity, event_type, reason);
        }
        let event = AgentEvent {
            event_type: event_type.to_string(),
            severity: severity.to_string(),
            metadata_json: Some(serde_json::json!({ "reason": reason }).to_string()),
        };
        if let Err(err) = self.backend.post_event(&event).await {
            tracing::warn!(error = %err, event_type, "could not deliver event");
        }
    }

    /// How long to wait after `outcome`: the signed policy's own heartbeat interval while healthy,
    /// exponential backoff while the backend is failing.
    pub fn next_delay(&mut self, outcome: TickOutcome, jitter: f64) -> Duration {
        if outcome == TickOutcome::Synced {
            self.consecutive_failures = 0;
            return self.policy_interval();
        }
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        backoff_delay(self.consecutive_failures, self.policy_interval(), self.config.max_backoff, jitter)
    }

    fn policy_interval(&self) -> Duration {
        match &self.cache.accepted {
            Some(a) => Duration::from_secs(a.policy.heartbeat_interval_seconds.max(0) as u64).clamp(MIN_INTERVAL, MAX_INTERVAL),
            None => self.config.default_interval.clamp(MIN_INTERVAL, MAX_INTERVAL),
        }
    }

    /// Runs until `shutdown` fires (or its sender is dropped, which means the process is going away).
    pub async fn run(mut self, mut shutdown: watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                break;
            }
            let started = tokio::time::Instant::now();
            let outcome = self.tick(unix_now()).await;
            // The interval is measured from the START of a pass, so a slow posture collection (several seconds
            // of PowerShell) does not stretch the heartbeat cadence. Never less than 1 s, so an overlong pass
            // cannot turn the loop into a busy spin.
            let delay = self.next_delay(outcome, rand::random::<f64>()).saturating_sub(started.elapsed()).max(Duration::from_secs(1));
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                }
            }
        }
        tracing::info!("sync loop stopped");
    }
}

pub fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy_verifier::test_support::{app, unsigned_policy, Fixture, DEVICE, TENANT};
    use crate::posture::{PostureError, Tri};
    use std::sync::atomic::AtomicUsize;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    #[derive(Default)]
    struct Shared {
        policies: Mutex<VecDeque<Result<DevicePolicyResponse, ApiError>>>,
        heartbeats: Mutex<Vec<(i32, String)>>,
        events: Mutex<Vec<(String, String, Option<String>)>>,
        postures: Mutex<Vec<PostureSignals>>,
        fail_heartbeat: AtomicBool,
        fail_posture: AtomicBool,
    }

    #[derive(Default)]
    struct RecordingSink(Mutex<Vec<(String, String)>>);
    impl LocalEventSink for RecordingSink {
        fn write(&self, severity: &str, event_type: &str, _message: &str) {
            self.0.lock().unwrap().push((severity.to_string(), event_type.to_string()));
        }
    }

    #[derive(Clone, Default)]
    struct FakeBackend(Arc<Shared>);

    impl FakeBackend {
        fn serve(&self, policy: DevicePolicyResponse) {
            self.0.policies.lock().unwrap().push_back(Ok(policy));
        }
        fn serve_error(&self) {
            self.0.policies.lock().unwrap().push_back(Err(ApiError::Backend { status: 503, body: "down".into() }));
        }
        fn heartbeats(&self) -> Vec<(i32, String)> {
            self.0.heartbeats.lock().unwrap().clone()
        }
        fn events(&self) -> Vec<(String, String, Option<String>)> {
            self.0.events.lock().unwrap().clone()
        }
        fn postures(&self) -> Vec<PostureSignals> {
            self.0.postures.lock().unwrap().clone()
        }
    }

    struct CollectorShared {
        result: Mutex<Result<PostureSignals, String>>,
        calls: AtomicUsize,
    }

    #[derive(Clone)]
    struct FakeCollector(Arc<CollectorShared>);

    impl Default for FakeCollector {
        fn default() -> Self {
            let healthy = PostureSignals { disk_encryption: Tri::Enabled, antivirus: Tri::Enabled, firewall: Tri::Enabled, ..Default::default() };
            Self(Arc::new(CollectorShared { result: Mutex::new(Ok(healthy)), calls: AtomicUsize::new(0) }))
        }
    }

    impl FakeCollector {
        fn calls(&self) -> usize {
            self.0.calls.load(Ordering::SeqCst)
        }
        fn fail_with(&self, message: &str) {
            *self.0.result.lock().unwrap() = Err(message.to_string());
        }
    }

    impl PostureCollector for FakeCollector {
        fn collect(&self) -> impl Future<Output = Result<PostureSignals, PostureError>> + Send {
            self.0.calls.fetch_add(1, Ordering::SeqCst);
            let result = self.0.result.lock().unwrap().clone().map_err(PostureError::Collect);
            async move { result }
        }
    }

    impl Backend for FakeBackend {
        fn fetch_policy(&self) -> impl Future<Output = Result<DevicePolicyResponse, ApiError>> + Send {
            let next = self.0.policies.lock().unwrap().pop_front();
            async move { next.unwrap_or(Err(ApiError::Backend { status: 503, body: "nothing queued".into() })) }
        }
        fn heartbeat(&self, request: &HeartbeatRequest) -> impl Future<Output = Result<(), ApiError>> + Send {
            self.0.heartbeats.lock().unwrap().push((request.policy_version, request.health_status.clone()));
            let fail = self.0.fail_heartbeat.load(Ordering::SeqCst);
            async move { if fail { Err(ApiError::Backend { status: 500, body: "boom".into() }) } else { Ok(()) } }
        }
        fn post_event(&self, event: &AgentEvent) -> impl Future<Output = Result<(), ApiError>> + Send {
            self.0.events.lock().unwrap().push((event.event_type.clone(), event.severity.clone(), event.metadata_json.clone()));
            async { Ok(()) }
        }
        fn report_posture(&self, signals: &PostureSignals) -> impl Future<Output = Result<(), ApiError>> + Send {
            let fail = self.0.fail_posture.load(Ordering::SeqCst);
            if !fail {
                self.0.postures.lock().unwrap().push(signals.clone());
            }
            async move { if fail { Err(ApiError::Backend { status: 500, body: "posture down".into() }) } else { Ok(()) } }
        }
    }

    const T0: i64 = 1_800_000_000;

    fn engine(f: &Fixture, backend: FakeBackend) -> (SyncEngine<FakeBackend, FakeCollector>, std::path::PathBuf) {
        engine_with(f, backend, FakeCollector::default())
    }

    fn engine_with(f: &Fixture, backend: FakeBackend, collector: FakeCollector) -> (SyncEngine<FakeBackend, FakeCollector>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("iam-sync-test-{}", Uuid::new_v4()));
        let path = dir.join("policy-cache.json");
        let config = SyncConfig {
            tenant_id: TENANT.parse().unwrap(),
            device_id: DEVICE.parse().unwrap(),
            transit_public_key_base64: f.public_key_b64.clone(),
            agent_version: "9.9.9".into(),
            default_interval: Duration::from_secs(300),
            max_backoff: Duration::from_secs(3600),
        };
        (SyncEngine::new(backend, collector, PolicyStore::new(&path), config).unwrap(), dir)
    }

    #[tokio::test]
    async fn tampering_with_a_watched_file_raises_an_event_and_degrades_health_until_restored() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (engine, dir) = engine(&f, backend.clone());
        std::fs::create_dir_all(&dir).unwrap();
        let watched = dir.join("config.json");
        std::fs::write(&watched, "original").unwrap();
        let mut engine = engine.with_integrity(IntegrityMonitor::baseline(vec![("config.json".into(), watched.clone())]));

        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        engine.tick(T0 + 5).await;
        assert_eq!(backend.heartbeats().last().unwrap().1, "HEALTHY");

        let sink = Arc::new(RecordingSink::default());
        engine = engine.with_local_log(sink.clone());
        std::fs::write(&watched, "tampered").unwrap();
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        engine.tick(T0 + 10).await;
        assert_eq!(backend.heartbeats().last().unwrap().1, "DEGRADED");
        assert!(backend.events().iter().any(|(t, sev, _)| t == "agent.tamper_detected" && sev == "CRITICAL"));
        assert!(
            sink.0.lock().unwrap().iter().any(|(sev, t)| t == "agent.tamper_detected" && sev == "CRITICAL"),
            "the local log must get the event too"
        );

        // Still tampered next tick: still degraded, but not alerted again.
        let alerts_before = backend.events().len();
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        engine.tick(T0 + 15).await;
        assert_eq!(backend.heartbeats().last().unwrap().1, "DEGRADED");
        assert_eq!(backend.events().len(), alerts_before);

        std::fs::write(&watched, "original").unwrap();
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        engine.tick(T0 + 20).await;
        assert_eq!(backend.heartbeats().last().unwrap().1, "HEALTHY");
        assert!(backend.events().iter().any(|(t, _, _)| t == "agent.tamper_cleared"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_good_policy_is_accepted_persisted_and_reported_as_healthy() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));

        assert_eq!(engine.tick(T0 + 5).await, TickOutcome::Synced);

        assert_eq!(engine.cache().policy_version(), 3);
        assert_eq!(backend.heartbeats(), vec![(3, "HEALTHY".to_string())]);
        assert!(backend.events().is_empty());
        let on_disk = PolicyStore::new(dir.join("policy-cache.json")).load().unwrap().unwrap();
        assert_eq!(on_disk.policy_version(), 3);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_restart_restores_the_last_known_good_policy_from_disk() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut first, dir) = engine(&f, backend.clone());
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        first.tick(T0 + 5).await;

        // Same file, brand-new engine, backend now down: it must still know policy v3.
        let config = SyncConfig {
            tenant_id: TENANT.parse().unwrap(),
            device_id: DEVICE.parse().unwrap(),
            transit_public_key_base64: f.public_key_b64.clone(),
            agent_version: "9.9.9".into(),
            default_interval: Duration::from_secs(300),
            max_backoff: Duration::from_secs(3600),
        };
        let second = SyncEngine::new(backend, FakeCollector::default(), PolicyStore::new(dir.join("policy-cache.json")), config).unwrap();
        assert_eq!(second.cache().policy_version(), 3);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn with_no_policy_and_no_backend_the_agent_reports_degraded_not_healthy() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        backend.serve_error();

        assert_eq!(engine.tick(T0).await, TickOutcome::SyncFailed);
        assert_eq!(backend.heartbeats(), vec![(0, "DEGRADED".to_string())]);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_transient_outage_with_a_still_fresh_policy_stays_healthy() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        engine.tick(T0 + 5).await;
        backend.serve_error();

        assert_eq!(engine.tick(T0 + 305).await, TickOutcome::SyncFailed);
        assert_eq!(backend.heartbeats().last().unwrap(), &(3, "HEALTHY".to_string()));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn once_the_cached_policy_lapses_the_agent_reports_degraded() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        engine.tick(T0 + 5).await;
        backend.serve_error();

        engine.tick(T0 + 5_000).await;
        assert_eq!(backend.heartbeats().last().unwrap(), &(3, "DEGRADED".to_string()));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_tampered_policy_is_refused_reported_and_does_not_replace_the_good_one() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        backend.serve(f.signed_policy(3, T0, 900, "SUSPENDED", vec![]));
        engine.tick(T0 + 5).await;

        let mut forged = f.signed_policy(4, T0 + 60, 900, "SUSPENDED", vec![]);
        forged.device_status = "APPROVED".into();
        backend.serve(forged);

        assert_eq!(engine.tick(T0 + 65).await, TickOutcome::PolicyRejected);
        assert_eq!(engine.cache().accepted.as_ref().unwrap().policy.device_status, "SUSPENDED");
        assert_eq!(engine.cache().policy_version(), 3);
        let (event_type, severity, metadata) = backend.events().remove(0);
        assert_eq!((event_type.as_str(), severity.as_str()), ("agent.policy_rejected", "CRITICAL"));
        assert!(metadata.unwrap().contains("signature"));
        assert_eq!(backend.heartbeats().last().unwrap().1, "DEGRADED");
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_validly_signed_policy_for_another_device_is_refused_as_a_replay() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        let mut other = unsigned_policy(3, T0, 900, "APPROVED", vec![]);
        other.device_id = "99999999-9999-9999-9999-999999999999".parse().unwrap();
        f.sign(&mut other);
        backend.serve(other);

        assert_eq!(engine.tick(T0 + 5).await, TickOutcome::PolicyRejected);
        assert!(engine.cache().accepted.is_none());
        assert!(backend.events()[0].2.as_ref().unwrap().contains("different device"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn an_older_policy_is_refused_as_a_rollback() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        backend.serve(f.signed_policy(5, T0, 900, "APPROVED", vec![app("44444444-4444-4444-4444-444444444444", false, false, 0, "FAIL_CLOSED")]));
        engine.tick(T0 + 5).await;
        backend.serve(f.signed_policy(4, T0 + 60, 900, "APPROVED", vec![]));

        assert_eq!(engine.tick(T0 + 65).await, TickOutcome::PolicyRejected);
        assert_eq!(engine.cache().policy_version(), 5);
        assert!(backend.events()[0].2.as_ref().unwrap().contains("VersionRolledBack"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_failing_heartbeat_makes_the_tick_a_failure_even_though_the_policy_synced() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        backend.0.fail_heartbeat.store(true, Ordering::SeqCst);
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));

        assert_eq!(engine.tick(T0 + 5).await, TickOutcome::SyncFailed);
        assert_eq!(engine.cache().policy_version(), 3); // the policy was still taken
        std::fs::remove_dir_all(dir).ok();
    }


    // ---- posture reporting ----

    fn policy_with_posture_interval(f: &Fixture, issued_at: i64, secs: i32) -> DevicePolicyResponse {
        let mut p = unsigned_policy(3, issued_at, 900, "APPROVED", vec![]);
        p.posture_interval_seconds = secs;
        f.sign(&mut p);
        p
    }

    #[tokio::test]
    async fn posture_is_reported_on_the_first_tick_stamped_with_the_collection_time() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));

        engine.tick(T0 + 5).await;

        let sent = backend.postures();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].collected_at, Some(T0 + 5));
        assert_eq!(sent[0].disk_encryption, Tri::Enabled);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn posture_is_not_collected_again_until_the_policys_interval_has_elapsed() {
        let (f, backend, collector) = (Fixture::new(), FakeBackend::default(), FakeCollector::default());
        let (mut engine, dir) = engine_with(&f, backend.clone(), collector.clone());
        backend.serve(policy_with_posture_interval(&f, T0, 900));
        engine.tick(T0 + 5).await;
        backend.serve(policy_with_posture_interval(&f, T0, 900));
        engine.tick(T0 + 305).await;
        assert_eq!(collector.calls(), 1, "still inside the 900 s interval");

        backend.serve(policy_with_posture_interval(&f, T0, 900));
        engine.tick(T0 + 5 + 900).await;
        assert_eq!((collector.calls(), backend.postures().len()), (2, 2));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn before_any_policy_exists_the_default_900_second_interval_applies() {
        let (f, backend, collector) = (Fixture::new(), FakeBackend::default(), FakeCollector::default());
        let (mut engine, dir) = engine_with(&f, backend.clone(), collector.clone());
        engine.tick(T0).await;
        engine.tick(T0 + 899).await;
        assert_eq!(collector.calls(), 1);
        engine.tick(T0 + 900).await;
        assert_eq!(collector.calls(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn an_absurdly_short_posture_interval_is_clamped_to_a_minute() {
        let (f, backend, collector) = (Fixture::new(), FakeBackend::default(), FakeCollector::default());
        let (mut engine, dir) = engine_with(&f, backend.clone(), collector.clone());
        backend.serve(policy_with_posture_interval(&f, T0, 1));
        engine.tick(T0 + 5).await;
        backend.serve(policy_with_posture_interval(&f, T0, 1));
        engine.tick(T0 + 30).await;
        assert_eq!(collector.calls(), 1, "a 1 s interval must not make the agent re-run PowerShell every tick");
        backend.serve(policy_with_posture_interval(&f, T0, 1));
        engine.tick(T0 + 66).await;
        assert_eq!(collector.calls(), 2);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_failing_collector_is_reported_once_per_interval_and_never_fails_the_tick() {
        let (f, backend, collector) = (Fixture::new(), FakeBackend::default(), FakeCollector::default());
        collector.fail_with("powershell timed out");
        let (mut engine, dir) = engine_with(&f, backend.clone(), collector.clone());
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));

        assert_eq!(engine.tick(T0 + 5).await, TickOutcome::Synced);
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        engine.tick(T0 + 305).await;

        assert_eq!(collector.calls(), 1, "a broken collector must not be re-run on every tick");
        assert!(backend.postures().is_empty());
        let events = backend.events();
        assert_eq!(events.len(), 1);
        assert_eq!((events[0].0.as_str(), events[0].1.as_str()), ("agent.posture_collection_failed", "WARNING"));
        assert!(events[0].2.as_ref().unwrap().contains("powershell timed out"));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn a_failed_upload_is_retried_on_the_very_next_tick_and_does_not_fail_the_tick() {
        let (f, backend, collector) = (Fixture::new(), FakeBackend::default(), FakeCollector::default());
        let (mut engine, dir) = engine_with(&f, backend.clone(), collector.clone());
        backend.0.fail_posture.store(true, Ordering::SeqCst);
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        assert_eq!(engine.tick(T0 + 5).await, TickOutcome::Synced);
        assert!(backend.postures().is_empty());

        backend.0.fail_posture.store(false, Ordering::SeqCst);
        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        engine.tick(T0 + 10).await;
        assert_eq!((collector.calls(), backend.postures().len()), (2, 1));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn posture_is_still_reported_when_the_policy_fetch_fails() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        backend.serve_error();
        assert_eq!(engine.tick(T0).await, TickOutcome::SyncFailed);
        assert_eq!(backend.postures().len(), 1);
        std::fs::remove_dir_all(dir).ok();
    }

    // ---- timing ----

    #[test]
    fn backoff_grows_exponentially_and_is_capped() {
        let (base, max) = (Duration::from_secs(300), Duration::from_secs(3600));
        let at = |n| backoff_delay(n, base, max, 0.5); // jitter 0.5 = exactly neutral
        assert_eq!(at(0), Duration::from_secs(300));
        assert_eq!(at(1), Duration::from_secs(600));
        assert_eq!(at(2), Duration::from_secs(1200));
        assert_eq!(at(3), Duration::from_secs(2400));
        assert_eq!(at(4), max);
        assert_eq!(at(1_000), max); // no shift overflow
    }

    #[test]
    fn jitter_stays_within_ten_percent_and_never_exceeds_the_cap() {
        let (base, max) = (Duration::from_secs(300), Duration::from_secs(3600));
        let close = |a: Duration, b: Duration| a.abs_diff(b) < Duration::from_millis(1); // float math: compare approximately
        assert!(close(backoff_delay(1, base, max, 0.0), Duration::from_secs(540))); // 600 * 0.9
        assert!(close(backoff_delay(1, base, max, 1.0), Duration::from_secs(660))); // 600 * 1.1
        assert!(backoff_delay(10, base, max, 1.0) <= max);
    }

    #[tokio::test]
    async fn the_delay_follows_the_signed_policys_interval_and_resets_after_a_success() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());

        // No policy yet: the configured default.
        assert_eq!(engine.next_delay(TickOutcome::Synced, 0.5), Duration::from_secs(300));

        backend.serve(f.signed_policy(3, T0, 900, "APPROVED", vec![]));
        engine.tick(T0 + 5).await;
        assert_eq!(engine.next_delay(TickOutcome::Synced, 0.5), Duration::from_secs(300)); // policy says 300

        assert_eq!(engine.next_delay(TickOutcome::SyncFailed, 0.5), Duration::from_secs(600));
        assert_eq!(engine.next_delay(TickOutcome::SyncFailed, 0.5), Duration::from_secs(1200));
        assert_eq!(engine.next_delay(TickOutcome::Synced, 0.5), Duration::from_secs(300)); // reset
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn an_absurd_policy_interval_is_clamped() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (mut engine, dir) = engine(&f, backend.clone());
        for (secs, expected) in [(0, 30), (5, 30), (10_000_000, 3600)] {
            let mut p = unsigned_policy(3, T0, 900, "APPROVED", vec![]);
            p.heartbeat_interval_seconds = secs;
            f.sign(&mut p);
            backend.serve(p);
            engine.tick(T0 + 5).await;
            assert_eq!(engine.next_delay(TickOutcome::Synced, 0.5), Duration::from_secs(expected), "interval {secs}");
        }
        std::fs::remove_dir_all(dir).ok();
    }

    // ---- the loop ----

    #[tokio::test(start_paused = true)]
    async fn run_keeps_ticking_until_shutdown_then_stops_promptly() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (engine, dir) = engine(&f, backend.clone());
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(engine.run(rx));

        // Paused time auto-advances while every task is idle, so this "waits" through several 300 s+ intervals instantly.
        tokio::time::sleep(Duration::from_secs(5_000)).await;
        assert!(backend.heartbeats().len() >= 3, "expected several heartbeats, got {}", backend.heartbeats().len());

        tx.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(1), handle).await.expect("loop must stop on shutdown").unwrap();
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test(start_paused = true)]
    async fn run_also_stops_if_the_shutdown_sender_is_dropped() {
        let (f, backend) = (Fixture::new(), FakeBackend::default());
        let (engine, dir) = engine(&f, backend);
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(engine.run(rx));
        tokio::time::sleep(Duration::from_secs(1)).await;
        drop(tx);
        tokio::time::timeout(Duration::from_secs(1), handle).await.expect("loop must stop when the sender goes away").unwrap();
        std::fs::remove_dir_all(dir).ok();
    }
}
