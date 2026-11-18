//! Signed agent updates (docs/specs/agent-update-SPEC.md, PDF P1-26).
//!
//! The agent installs a new version only if it can prove, by itself, that the release was signed by the operator's
//! `agent-release` key (whose public half is in this machine's administrator-only config):
//!   1. the signature over the signed statement verifies,
//!   2. the downloaded file hashes to exactly the signed checksum,
//!   3. the signed version is strictly NEWER than the one running (so a validly signed but older release with a known bug
//!      cannot be replayed to downgrade a laptop).
//! The platform only serves files; it cannot make the agent accept one. No key in the config means updates are off, and
//! nothing the platform sends can switch them on.
//!
//! Everything that touches the network, the disk's installer, or the clock is behind a trait, so every refusal below is unit
//! tested with fakes and no real install ever happens in a test.

use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::future::Future;
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const MAX_PACKAGE_BYTES: u64 = 64 * 1024 * 1024;
const STATEMENT_LABEL: &str = "iam-agent-release-v1";
/// What this agent is: the platform and architecture it will accept a release for.
pub const THIS_PLATFORM: &str = "WINDOWS";
pub const THIS_ARCHITECTURE: &str = "x86_64";

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseOffer {
    pub release_id: Uuid,
    pub version: String,
    pub platform: String,
    pub architecture: String,
    pub sha256: String,
    pub signature: String,
    pub size_bytes: u64,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum UpdateRejection {
    #[error("no release signing key is configured on this device")]
    NoKey,
    #[error("the configured release signing key is not a valid Ed25519 key")]
    BadKey,
    #[error("the release is for {0}/{1}, not this machine")]
    WrongTarget(String, String),
    #[error("the release version {0:?} is not a valid x.y.z version")]
    BadVersion(String),
    #[error("version {offered} is not newer than the running version {current}")]
    NotNewer { offered: String, current: String },
    #[error("the release is {0} bytes, over the {MAX_PACKAGE_BYTES} byte limit")]
    TooLarge(u64),
    #[error("the release signature is not valid for this device's release key")]
    BadSignature,
    #[error("the downloaded file does not match the signed checksum")]
    HashMismatch,
}

/// `x.y.z` only. Anything else is not a version this agent will ever treat as newer.
pub fn parse_version(v: &str) -> Option<(u32, u32, u32)> {
    let mut parts = v.trim().split('.');
    let (a, b, c) = (parts.next()?.parse().ok()?, parts.next()?.parse().ok()?, parts.next()?.parse().ok()?);
    if parts.next().is_some() {
        return None;
    }
    Some((a, b, c))
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(a), Some(b)) => a > b,
        (Some(_), None) => true, // the running version is unparseable: any valid release is an improvement
        _ => false,
    }
}

/// The exact text the operator signs. MUST match infra/agent-release/publish.py and AgentReleases.kt.
pub fn release_statement(platform: &str, architecture: &str, version: &str, sha256_hex: &str) -> String {
    [STATEMENT_LABEL, platform, architecture, version, sha256_hex].join("\n")
}

fn load_key(key_b64: Option<&str>) -> Result<VerifyingKey, UpdateRejection> {
    let key_b64 = key_b64.map(str::trim).filter(|k| !k.is_empty()).ok_or(UpdateRejection::NoKey)?;
    let raw: [u8; 32] = STANDARD.decode(key_b64).map_err(|_| UpdateRejection::BadKey)?.try_into().map_err(|_| UpdateRejection::BadKey)?;
    VerifyingKey::from_bytes(&raw).map_err(|_| UpdateRejection::BadKey)
}

/// Everything that can be decided BEFORE downloading: target, size, version order and, above all, the signature over the
/// release statement. A hostile server therefore cannot even make the agent download a file that was not signed for it.
pub fn verify_offer(offer: &ReleaseOffer, current_version: &str, release_key_b64: Option<&str>) -> Result<(), UpdateRejection> {
    let key = load_key(release_key_b64)?;
    if offer.platform != THIS_PLATFORM || offer.architecture != THIS_ARCHITECTURE {
        return Err(UpdateRejection::WrongTarget(offer.platform.clone(), offer.architecture.clone()));
    }
    if parse_version(&offer.version).is_none() {
        return Err(UpdateRejection::BadVersion(offer.version.clone()));
    }
    if !is_newer(&offer.version, current_version) {
        return Err(UpdateRejection::NotNewer { offered: offer.version.clone(), current: current_version.to_string() });
    }
    if offer.size_bytes == 0 || offer.size_bytes > MAX_PACKAGE_BYTES {
        return Err(UpdateRejection::TooLarge(offer.size_bytes));
    }
    // OpenBao prefixes transit signatures with "vault:v<n>:".
    let raw_sig = offer.signature.rsplit(':').next().unwrap_or("");
    let sig_bytes: [u8; 64] = STANDARD.decode(raw_sig).map_err(|_| UpdateRejection::BadSignature)?.try_into().map_err(|_| UpdateRejection::BadSignature)?;
    let statement = release_statement(&offer.platform, &offer.architecture, &offer.version, &offer.sha256.to_ascii_lowercase());
    key.verify_strict(statement.as_bytes(), &Signature::from_bytes(&sig_bytes)).map_err(|_| UpdateRejection::BadSignature)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// The downloaded bytes must be exactly what was signed.
pub fn verify_package(offer: &ReleaseOffer, bytes: &[u8]) -> Result<(), UpdateRejection> {
    if bytes.len() as u64 != offer.size_bytes || sha256_hex(bytes) != offer.sha256.to_ascii_lowercase() {
        return Err(UpdateRejection::HashMismatch);
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------------

/// Where releases come from. Production: the platform, authenticated like every other device call.
pub trait UpdateSource: Send + Sync {
    fn check(&self, current_version: &str) -> impl Future<Output = Result<Option<ReleaseOffer>, String>> + Send;
    fn download(&self, offer: &ReleaseOffer) -> impl Future<Output = Result<Vec<u8>, String>> + Send;
}

/// Starts the installer for a verified file. Production (Windows): a detached `msiexec`.
pub trait UpdateInstaller: Send + Sync {
    fn install(&self, package: &Path) -> Result<(), String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateOutcome {
    UpToDate,
    /// The installer was started; the service is about to be replaced and restarted by it.
    Installing { version: String },
    /// Refused on a security rule. Reported as CRITICAL: someone served the device something it should not trust.
    Rejected { version: String, reason: UpdateRejection },
    /// An operational failure (network, disk, installer could not start). Retried at the next check.
    Failed(String),
}

fn clear_old_packages(dir: &Path) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if entry.path().extension().is_some_and(|e| e.eq_ignore_ascii_case("msi")) {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

/// One full pass: ask, verify the offer, download, verify the bytes, put them on disk, verify AGAIN from disk, install.
pub async fn check_and_install<S: UpdateSource, I: UpdateInstaller>(
    source: &S,
    installer: &I,
    release_key_b64: Option<&str>,
    current_version: &str,
    updates_dir: &Path,
) -> UpdateOutcome {
    let offer = match source.check(current_version).await {
        Ok(None) => return UpdateOutcome::UpToDate,
        Ok(Some(offer)) => offer,
        Err(err) => return UpdateOutcome::Failed(format!("update check failed: {err}")),
    };
    if let Err(reason) = verify_offer(&offer, current_version, release_key_b64) {
        return UpdateOutcome::Rejected { version: offer.version, reason };
    }
    let bytes = match source.download(&offer).await {
        Ok(b) => b,
        Err(err) => return UpdateOutcome::Failed(format!("download failed: {err}")),
    };
    if let Err(reason) = verify_package(&offer, &bytes) {
        return UpdateOutcome::Rejected { version: offer.version, reason };
    }

    if let Err(err) = std::fs::create_dir_all(updates_dir) {
        return UpdateOutcome::Failed(format!("cannot create the update folder: {err}"));
    }
    clear_old_packages(updates_dir);
    let path: PathBuf = updates_dir.join(format!("IamEndpointAgent-{}.msi", offer.version));
    if let Err(err) = std::fs::write(&path, &bytes) {
        return UpdateOutcome::Failed(format!("cannot write the package: {err}"));
    }
    // The file sits on disk between verification and use: read it back and check it again, so a swap in that gap is caught.
    match std::fs::read(&path) {
        Ok(on_disk) if verify_package(&offer, &on_disk).is_ok() => {}
        Ok(_) => {
            let _ = std::fs::remove_file(&path);
            return UpdateOutcome::Rejected { version: offer.version, reason: UpdateRejection::HashMismatch };
        }
        Err(err) => return UpdateOutcome::Failed(format!("cannot read the package back: {err}")),
    }

    match installer.install(&path) {
        Ok(()) => UpdateOutcome::Installing { version: offer.version },
        Err(err) => UpdateOutcome::Failed(format!("could not start the installer: {err}")),
    }
}

// ---------------------------------------------------------------------------------------------------------------------
// Production wiring: where offers come from, and the background loop.

/// The platform as an update source: the same device-signed requests as the policy fetch.
pub struct PlatformUpdateSource {
    pub api: crate::api_client::ApiClient,
    pub tenant_id: String,
    pub device_id: Uuid,
    pub key: std::sync::Arc<dyn crate::key_provider::KeyProvider>,
}

impl UpdateSource for PlatformUpdateSource {
    fn check(&self, current_version: &str) -> impl Future<Output = Result<Option<ReleaseOffer>, String>> + Send {
        let current = current_version.to_string();
        async move { self.api.agent_update_offer(&self.tenant_id, self.device_id, self.key.as_ref(), &current).await.map_err(|e| e.to_string()) }
    }

    fn download(&self, offer: &ReleaseOffer) -> impl Future<Output = Result<Vec<u8>, String>> + Send {
        let release_id = offer.release_id;
        async move { self.api.agent_update_package(&self.tenant_id, self.device_id, self.key.as_ref(), release_id).await.map_err(|e| e.to_string()) }
    }
}

/// Delivers an update event to the platform and the device's own log. Must never block or fail the caller.
pub trait UpdateReporter: Send + Sync {
    fn report(&self, event_type: &str, severity: &str, detail: &str);
}

pub const FIRST_CHECK_DELAY: std::time::Duration = std::time::Duration::from_secs(300);
pub const CHECK_INTERVAL: std::time::Duration = std::time::Duration::from_secs(6 * 3600);

pub fn report_outcome(outcome: &UpdateOutcome, reporter: &dyn UpdateReporter) {
    match outcome {
        UpdateOutcome::UpToDate => {}
        UpdateOutcome::Installing { version } => reporter.report("agent.update_installing", "INFO", &format!("installing version {version}")),
        UpdateOutcome::Rejected { version, reason } => reporter.report("agent.update_rejected", "CRITICAL", &format!("version {version} refused: {reason}")),
        UpdateOutcome::Failed(detail) => reporter.report("agent.update_failed", "WARNING", detail),
    }
}

/// Checks 5 minutes after start (never at the very start: that is when the machine is busiest), then every 6 hours, until
/// shutdown. A pass never panics and never touches the sync loop.
pub async fn run_update_loop<S: UpdateSource, I: UpdateInstaller>(
    source: S,
    installer: I,
    release_key_b64: String,
    current_version: String,
    updates_dir: PathBuf,
    reporter: std::sync::Arc<dyn UpdateReporter>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut delay = FIRST_CHECK_DELAY;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
                continue;
            }
        }
        let outcome = check_and_install(&source, &installer, Some(&release_key_b64), &current_version, &updates_dir).await;
        tracing::info!(?outcome, "update check finished");
        report_outcome(&outcome, reporter.as_ref());
        delay = CHECK_INTERVAL;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use std::sync::Mutex;

    const BYTES: &[u8] = b"pretend this is an MSI";

    struct Fixture {
        key: SigningKey,
        key_b64: String,
    }

    impl Fixture {
        fn new() -> Self {
            let key = SigningKey::generate(&mut OsRng);
            let key_b64 = STANDARD.encode(key.verifying_key().as_bytes());
            Self { key, key_b64 }
        }

        fn offer(&self, version: &str, bytes: &[u8]) -> ReleaseOffer {
            let sha = sha256_hex(bytes);
            let statement = release_statement(THIS_PLATFORM, THIS_ARCHITECTURE, version, &sha);
            let signature = format!("vault:v1:{}", STANDARD.encode(self.key.sign(statement.as_bytes()).to_bytes()));
            ReleaseOffer {
                release_id: Uuid::new_v4(),
                version: version.to_string(),
                platform: THIS_PLATFORM.to_string(),
                architecture: THIS_ARCHITECTURE.to_string(),
                sha256: sha,
                signature,
                size_bytes: bytes.len() as u64,
            }
        }
    }

    // ---- the rules ---------------------------------------------------------------------------------------------

    #[test]
    fn versions_compare_numerically() {
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("0.2.0", "0.2.0"));
        assert!(!is_newer("0.1.9", "0.2.0"));
        assert!(!is_newer("1.2", "0.1.0"));
        assert!(!is_newer("1.2.3.4", "0.1.0"));
        assert!(!is_newer("a.b.c", "0.1.0"));
        assert!(!is_newer("-1.0.0", "0.1.0"));
        assert!(is_newer("0.3.0", "weird"));
    }

    #[test]
    fn a_correctly_signed_newer_offer_is_accepted() {
        let f = Fixture::new();
        assert_eq!(verify_offer(&f.offer("0.3.0", BYTES), "0.2.0", Some(&f.key_b64)), Ok(()));
    }

    #[test]
    fn no_key_means_updates_are_off_and_a_bad_key_is_refused() {
        let f = Fixture::new();
        let offer = f.offer("0.3.0", BYTES);
        assert_eq!(verify_offer(&offer, "0.2.0", None), Err(UpdateRejection::NoKey));
        assert_eq!(verify_offer(&offer, "0.2.0", Some("")), Err(UpdateRejection::NoKey));
        assert_eq!(verify_offer(&offer, "0.2.0", Some("   ")), Err(UpdateRejection::NoKey));
        assert_eq!(verify_offer(&offer, "0.2.0", Some("not base64!!")), Err(UpdateRejection::BadKey));
        assert_eq!(verify_offer(&offer, "0.2.0", Some(&STANDARD.encode([1u8; 8]))), Err(UpdateRejection::BadKey));
    }

    #[test]
    fn a_release_signed_by_a_different_key_is_refused() {
        let (real, attacker) = (Fixture::new(), Fixture::new());
        let forged = attacker.offer("0.3.0", BYTES);
        assert_eq!(verify_offer(&forged, "0.2.0", Some(&real.key_b64)), Err(UpdateRejection::BadSignature));
    }

    #[test]
    fn changing_any_signed_field_breaks_the_signature() {
        let f = Fixture::new();
        let good = f.offer("0.3.0", BYTES);
        let mut v = good.clone();
        v.version = "0.9.0".into();
        assert_eq!(verify_offer(&v, "0.2.0", Some(&f.key_b64)), Err(UpdateRejection::BadSignature));
        let mut h = good.clone();
        h.sha256 = sha256_hex(b"something else");
        assert_eq!(verify_offer(&h, "0.2.0", Some(&f.key_b64)), Err(UpdateRejection::BadSignature));
        let mut s = good.clone();
        s.signature = "AAAA".into();
        assert_eq!(verify_offer(&s, "0.2.0", Some(&f.key_b64)), Err(UpdateRejection::BadSignature));
    }

    #[test]
    fn a_downgrade_or_a_same_version_replay_is_refused_even_when_validly_signed() {
        let f = Fixture::new();
        assert!(matches!(verify_offer(&f.offer("0.1.0", BYTES), "0.2.0", Some(&f.key_b64)), Err(UpdateRejection::NotNewer { .. })));
        assert!(matches!(verify_offer(&f.offer("0.2.0", BYTES), "0.2.0", Some(&f.key_b64)), Err(UpdateRejection::NotNewer { .. })));
    }

    #[test]
    fn wrong_platform_unparseable_version_and_absurd_size_are_refused() {
        let f = Fixture::new();
        let mut mac = f.offer("0.3.0", BYTES);
        mac.platform = "MACOS".into();
        assert!(matches!(verify_offer(&mac, "0.2.0", Some(&f.key_b64)), Err(UpdateRejection::WrongTarget(..))));
        let mut arm = f.offer("0.3.0", BYTES);
        arm.architecture = "aarch64".into();
        assert!(matches!(verify_offer(&arm, "0.2.0", Some(&f.key_b64)), Err(UpdateRejection::WrongTarget(..))));
        let mut ver = f.offer("0.3.0", BYTES);
        ver.version = "latest".into();
        assert!(matches!(verify_offer(&ver, "0.2.0", Some(&f.key_b64)), Err(UpdateRejection::BadVersion(_))));
        let mut big = f.offer("0.3.0", BYTES);
        big.size_bytes = MAX_PACKAGE_BYTES + 1;
        assert!(matches!(verify_offer(&big, "0.2.0", Some(&f.key_b64)), Err(UpdateRejection::TooLarge(_))));
        let mut zero = f.offer("0.3.0", BYTES);
        zero.size_bytes = 0;
        assert!(matches!(verify_offer(&zero, "0.2.0", Some(&f.key_b64)), Err(UpdateRejection::TooLarge(0))));
    }

    #[test]
    fn the_downloaded_bytes_must_match_the_signed_checksum_and_size() {
        let f = Fixture::new();
        let offer = f.offer("0.3.0", BYTES);
        assert_eq!(verify_package(&offer, BYTES), Ok(()));
        assert_eq!(verify_package(&offer, b"pretend this is an MSI!"), Err(UpdateRejection::HashMismatch));
        assert_eq!(verify_package(&offer, b""), Err(UpdateRejection::HashMismatch));
        let mut short = offer.clone();
        short.size_bytes -= 1;
        assert_eq!(verify_package(&short, BYTES), Err(UpdateRejection::HashMismatch));
    }

    #[test]
    fn the_statement_has_the_exact_shape_the_operator_signs() {
        assert_eq!(release_statement("WINDOWS", "x86_64", "0.3.1", "ab"), "iam-agent-release-v1\nWINDOWS\nx86_64\n0.3.1\nab");
    }

    // ---- the whole pass, with fakes ----------------------------------------------------------------------------

    struct FakeSource {
        offer: Option<ReleaseOffer>,
        bytes: Vec<u8>,
        fail_check: bool,
        fail_download: bool,
        downloads: Mutex<u32>,
    }

    impl FakeSource {
        fn new(offer: Option<ReleaseOffer>, bytes: &[u8]) -> Self {
            Self { offer, bytes: bytes.to_vec(), fail_check: false, fail_download: false, downloads: Mutex::new(0) }
        }
    }

    impl UpdateSource for FakeSource {
        fn check(&self, _current: &str) -> impl Future<Output = Result<Option<ReleaseOffer>, String>> + Send {
            let r = if self.fail_check { Err("network down".to_string()) } else { Ok(self.offer.clone()) };
            async move { r }
        }
        fn download(&self, _offer: &ReleaseOffer) -> impl Future<Output = Result<Vec<u8>, String>> + Send {
            *self.downloads.lock().unwrap() += 1;
            let r = if self.fail_download { Err("reset".to_string()) } else { Ok(self.bytes.clone()) };
            async move { r }
        }
    }

    #[derive(Default)]
    struct FakeInstaller {
        installed: Mutex<Vec<PathBuf>>,
        fail: bool,
    }

    impl UpdateInstaller for FakeInstaller {
        fn install(&self, package: &Path) -> Result<(), String> {
            if self.fail {
                return Err("msiexec missing".into());
            }
            self.installed.lock().unwrap().push(package.to_path_buf());
            Ok(())
        }
    }

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!("iam-update-{}", Uuid::new_v4()))
    }

    #[tokio::test]
    async fn a_good_release_is_downloaded_verified_written_and_handed_to_the_installer() {
        let (f, dir) = (Fixture::new(), temp_dir());
        let source = FakeSource::new(Some(f.offer("0.3.0", BYTES)), BYTES);
        let installer = FakeInstaller::default();
        let outcome = check_and_install(&source, &installer, Some(&f.key_b64), "0.2.0", &dir).await;
        assert_eq!(outcome, UpdateOutcome::Installing { version: "0.3.0".into() });
        let installed = installer.installed.lock().unwrap();
        assert_eq!(installed.len(), 1);
        assert_eq!(std::fs::read(&installed[0]).unwrap(), BYTES);
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn nothing_newer_means_up_to_date_and_nothing_is_downloaded() {
        let (f, dir) = (Fixture::new(), temp_dir());
        let source = FakeSource::new(None, BYTES);
        let outcome = check_and_install(&source, &FakeInstaller::default(), Some(&f.key_b64), "0.2.0", &dir).await;
        assert_eq!(outcome, UpdateOutcome::UpToDate);
        assert_eq!(*source.downloads.lock().unwrap(), 0);
    }

    #[tokio::test]
    async fn a_forged_offer_is_rejected_before_anything_is_downloaded_or_run() {
        let (real, attacker, dir) = (Fixture::new(), Fixture::new(), temp_dir());
        let source = FakeSource::new(Some(attacker.offer("0.3.0", BYTES)), BYTES);
        let installer = FakeInstaller::default();
        let outcome = check_and_install(&source, &installer, Some(&real.key_b64), "0.2.0", &dir).await;
        assert!(matches!(outcome, UpdateOutcome::Rejected { reason: UpdateRejection::BadSignature, .. }));
        assert_eq!(*source.downloads.lock().unwrap(), 0, "an unsigned release must not even be downloaded");
        assert!(installer.installed.lock().unwrap().is_empty());
        assert!(!dir.exists(), "nothing was written either");
    }

    #[tokio::test]
    async fn a_tampered_download_is_rejected_and_never_reaches_the_installer_or_the_disk() {
        let (f, dir) = (Fixture::new(), temp_dir());
        let source = FakeSource::new(Some(f.offer("0.3.0", BYTES)), b"pretend this is an EVIL msi");
        let installer = FakeInstaller::default();
        let outcome = check_and_install(&source, &installer, Some(&f.key_b64), "0.2.0", &dir).await;
        assert!(matches!(outcome, UpdateOutcome::Rejected { reason: UpdateRejection::HashMismatch, .. }));
        assert!(installer.installed.lock().unwrap().is_empty());
        assert!(!dir.exists());
    }

    #[tokio::test]
    async fn a_replayed_older_signed_release_does_not_downgrade_the_device() {
        let (f, dir) = (Fixture::new(), temp_dir());
        let source = FakeSource::new(Some(f.offer("0.1.0", BYTES)), BYTES);
        let installer = FakeInstaller::default();
        let outcome = check_and_install(&source, &installer, Some(&f.key_b64), "0.2.0", &dir).await;
        assert!(matches!(outcome, UpdateOutcome::Rejected { reason: UpdateRejection::NotNewer { .. }, .. }));
        assert!(installer.installed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn with_no_key_configured_even_a_perfectly_signed_release_is_not_installed() {
        let (f, dir) = (Fixture::new(), temp_dir());
        let source = FakeSource::new(Some(f.offer("0.3.0", BYTES)), BYTES);
        let installer = FakeInstaller::default();
        let outcome = check_and_install(&source, &installer, None, "0.2.0", &dir).await;
        assert!(matches!(outcome, UpdateOutcome::Rejected { reason: UpdateRejection::NoKey, .. }));
        assert!(installer.installed.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn network_and_installer_failures_are_operational_not_security_events() {
        let (f, dir) = (Fixture::new(), temp_dir());
        let mut down = FakeSource::new(Some(f.offer("0.3.0", BYTES)), BYTES);
        down.fail_check = true;
        assert!(matches!(check_and_install(&down, &FakeInstaller::default(), Some(&f.key_b64), "0.2.0", &dir).await, UpdateOutcome::Failed(_)));
        let mut reset = FakeSource::new(Some(f.offer("0.3.0", BYTES)), BYTES);
        reset.fail_download = true;
        assert!(matches!(check_and_install(&reset, &FakeInstaller::default(), Some(&f.key_b64), "0.2.0", &dir).await, UpdateOutcome::Failed(_)));
        let ok = FakeSource::new(Some(f.offer("0.3.0", BYTES)), BYTES);
        let broken = FakeInstaller { fail: true, ..Default::default() };
        assert!(matches!(check_and_install(&ok, &broken, Some(&f.key_b64), "0.2.0", &dir).await, UpdateOutcome::Failed(_)));
        std::fs::remove_dir_all(dir).ok();
    }

    #[tokio::test]
    async fn old_packages_are_cleared_before_a_new_one_is_written() {
        let (f, dir) = (Fixture::new(), temp_dir());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("IamEndpointAgent-0.2.5.msi"), b"stale").unwrap();
        std::fs::write(dir.join("install.log"), b"keep").unwrap();
        let source = FakeSource::new(Some(f.offer("0.3.0", BYTES)), BYTES);
        check_and_install(&source, &FakeInstaller::default(), Some(&f.key_b64), "0.2.0", &dir).await;
        assert!(!dir.join("IamEndpointAgent-0.2.5.msi").exists());
        assert!(dir.join("IamEndpointAgent-0.3.0.msi").exists());
        assert!(dir.join("install.log").exists(), "only installers are cleared");
        std::fs::remove_dir_all(dir).ok();
    }

    // ---- reporting -----------------------------------------------------------------------------------------------

    #[derive(Default)]
    struct Recorder(Mutex<Vec<(String, String)>>);
    impl UpdateReporter for Recorder {
        fn report(&self, event_type: &str, severity: &str, _detail: &str) {
            self.0.lock().unwrap().push((event_type.to_string(), severity.to_string()));
        }
    }

    #[test]
    fn each_outcome_is_reported_with_the_right_severity_and_up_to_date_is_silent() {
        let r = Recorder::default();
        report_outcome(&UpdateOutcome::UpToDate, &r);
        report_outcome(&UpdateOutcome::Installing { version: "0.3.0".into() }, &r);
        report_outcome(&UpdateOutcome::Rejected { version: "0.3.0".into(), reason: UpdateRejection::BadSignature }, &r);
        report_outcome(&UpdateOutcome::Failed("x".into()), &r);
        assert_eq!(
            *r.0.lock().unwrap(),
            vec![
                ("agent.update_installing".to_string(), "INFO".to_string()),
                ("agent.update_rejected".to_string(), "CRITICAL".to_string()),
                ("agent.update_failed".to_string(), "WARNING".to_string()),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_loop_waits_five_minutes_then_checks_then_every_six_hours_and_stops_on_shutdown() {
        let (f, dir) = (Fixture::new(), temp_dir());
        let source = std::sync::Arc::new(FakeSource::new(Some(f.offer("0.3.0", BYTES)), BYTES));
        struct Shared(std::sync::Arc<FakeSource>);
        impl UpdateSource for Shared {
            fn check(&self, c: &str) -> impl Future<Output = Result<Option<ReleaseOffer>, String>> + Send {
                self.0.check(c)
            }
            fn download(&self, o: &ReleaseOffer) -> impl Future<Output = Result<Vec<u8>, String>> + Send {
                self.0.download(o)
            }
        }
        let recorder = std::sync::Arc::new(Recorder::default());
        let (tx, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run_update_loop(Shared(source.clone()), FakeInstaller::default(), f.key_b64.clone(), "0.2.0".into(), dir.clone(), recorder.clone(), rx));

        tokio::time::sleep(FIRST_CHECK_DELAY - std::time::Duration::from_secs(1)).await;
        assert_eq!(*source.downloads.lock().unwrap(), 0, "no check before the first delay");
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        assert_eq!(*source.downloads.lock().unwrap(), 1, "first check after five minutes");
        tokio::time::sleep(CHECK_INTERVAL + std::time::Duration::from_secs(5)).await;
        assert_eq!(*source.downloads.lock().unwrap(), 2, "then every six hours");

        tx.send(true).unwrap();
        task.await.unwrap();
        assert!(!recorder.0.lock().unwrap().is_empty());
        std::fs::remove_dir_all(dir).ok();
    }

    /// Run only by the interop harness (`cargo test -- --ignored`) against a REAL OpenBao: the signature there was made by
    /// OpenBao's transit engine over the statement that infra/agent-release/publish.py builds. This proves the three
    /// implementations (operator tool, OpenBao, agent) agree on the bytes, which no mock can.
    #[test]
    #[ignore]
    fn interop_a_release_signed_by_a_real_openbao_verifies_and_a_tampered_one_does_not() {
        let key = std::env::var("INTEROP_RELEASE_KEY").expect("INTEROP_RELEASE_KEY");
        let file = std::fs::read(std::env::var("INTEROP_RELEASE_FILE").expect("INTEROP_RELEASE_FILE")).expect("release file");
        let json: serde_json::Value = serde_json::from_str(&std::env::var("INTEROP_RELEASE_JSON").expect("INTEROP_RELEASE_JSON")).expect("json");
        let offer = ReleaseOffer {
            release_id: Uuid::new_v4(),
            version: json["version"].as_str().unwrap().to_string(),
            platform: json["platform"].as_str().unwrap().to_string(),
            architecture: json["architecture"].as_str().unwrap().to_string(),
            sha256: json["sha256"].as_str().unwrap().to_string(),
            signature: json["signature"].as_str().unwrap().to_string(),
            size_bytes: file.len() as u64,
        };
        assert_eq!(verify_offer(&offer, "0.0.1", Some(&key)), Ok(()), "OpenBao's signature must verify in the agent");
        assert_eq!(verify_package(&offer, &file), Ok(()));
        let mut tampered = file.clone();
        tampered[0] ^= 0xff;
        assert_eq!(verify_package(&offer, &tampered), Err(UpdateRejection::HashMismatch));
        assert!(matches!(verify_offer(&offer, &offer.version, Some(&key)), Err(UpdateRejection::NotNewer { .. })));
        let mut other_version = offer.clone();
        other_version.version = "9.9.9".into();
        assert_eq!(verify_offer(&other_version, "0.0.1", Some(&key)), Err(UpdateRejection::BadSignature));
        println!("INTEROP_RELEASE_OK");
    }

    // ---- a signature produced exactly the way the operator tool does, with a deterministic key -----------------

    #[test]
    fn a_signature_from_an_openbao_style_prefixed_value_verifies() {
        let f = Fixture::new();
        let offer = f.offer("0.3.0", BYTES);
        assert!(offer.signature.starts_with("vault:v1:"));
        assert_eq!(verify_offer(&offer, "0.2.0", Some(&f.key_b64)), Ok(()));
        let mut bare = offer.clone();
        bare.signature = bare.signature.trim_start_matches("vault:v1:").to_string();
        assert_eq!(verify_offer(&bare, "0.2.0", Some(&f.key_b64)), Ok(()), "a bare base64 signature is accepted too");
    }
}
