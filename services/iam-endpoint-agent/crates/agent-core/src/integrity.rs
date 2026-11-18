//! Tamper detection (spec P1-16): notice when the agent's own program file or configuration is changed or
//! deleted while it is running, and say so.
//!
//! The monitor records a SHA-256 of each watched file when the agent starts (the baseline) and compares on every
//! sync tick. A deviation is reported ONCE per distinct state (so a modified file does not raise an alert every
//! 5 minutes), and a change back to the baseline is reported as recovery. While any file deviates the agent
//! reports DEGRADED health. A legitimate change (an administrator edits the config, an update replaces the exe)
//! is followed by a service restart, which takes a fresh baseline.
//!
//! Limits, stated plainly: this detects edits to files while the agent runs. It does not stop the service being
//! stopped or killed, and an attacker with SYSTEM rights can replace the files and restart the service. Stronger
//! protection (service hardening, signed-binary checks, a watchdog) is separate work.

use sha2::{Digest, Sha256};
use std::path::PathBuf;

type Digest32 = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingKind {
    Modified,
    Deleted,
    Restored,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegrityFinding {
    pub label: String,
    pub kind: FindingKind,
}

struct Watched {
    label: String,
    path: PathBuf,
    baseline: Option<Digest32>,
    /// The state last reported, so an unchanged tampered file is not re-reported on every check.
    last_seen: Option<Digest32>,
}

pub struct IntegrityMonitor {
    files: Vec<Watched>,
}

fn digest_of(path: &PathBuf) -> Option<Digest32> {
    std::fs::read(path).ok().map(|bytes| Sha256::digest(bytes).into())
}

impl IntegrityMonitor {
    /// Takes the baseline now. A file that cannot be read at this point is simply not protected (its baseline
    /// is "absent"), which is reported by [`IntegrityMonitor::unprotected`] so it is visible, not silent.
    pub fn baseline(files: Vec<(String, PathBuf)>) -> Self {
        let files = files
            .into_iter()
            .map(|(label, path)| {
                let d = digest_of(&path);
                Watched { label, path, baseline: d, last_seen: d }
            })
            .collect();
        Self { files }
    }

    pub fn unprotected(&self) -> Vec<&str> {
        self.files.iter().filter(|f| f.baseline.is_none()).map(|f| f.label.as_str()).collect()
    }

    /// Compares every watched file with its baseline; returns only what changed since the last call.
    pub fn check(&mut self) -> Vec<IntegrityFinding> {
        let mut findings = Vec::new();
        for f in &mut self.files {
            let Some(baseline) = f.baseline else { continue };
            let now = digest_of(&f.path);
            if now == f.last_seen {
                continue;
            }
            f.last_seen = now;
            let kind = match now {
                None => FindingKind::Deleted,
                Some(d) if d == baseline => FindingKind::Restored,
                Some(_) => FindingKind::Modified,
            };
            findings.push(IntegrityFinding { label: f.label.clone(), kind });
        }
        findings
    }

    /// True while any watched file differs from its baseline.
    pub fn is_compromised(&self) -> bool {
        self.files.iter().any(|f| f.baseline.is_some() && f.last_seen != f.baseline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn temp_file(content: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("iam-integrity-{}", Uuid::new_v4()));
        std::fs::write(&p, content).unwrap();
        p
    }

    fn monitor(p: &PathBuf) -> IntegrityMonitor {
        IntegrityMonitor::baseline(vec![("config".into(), p.clone())])
    }

    #[test]
    fn unchanged_file_reports_nothing() {
        let p = temp_file("a");
        let mut m = monitor(&p);
        assert!(m.check().is_empty());
        assert!(!m.is_compromised());
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn modification_is_reported_once_then_stays_compromised() {
        let p = temp_file("a");
        let mut m = monitor(&p);
        std::fs::write(&p, "b").unwrap();
        assert_eq!(m.check(), vec![IntegrityFinding { label: "config".into(), kind: FindingKind::Modified }]);
        assert!(m.is_compromised());
        assert!(m.check().is_empty(), "the same tampered state must not be re-reported");
        assert!(m.is_compromised());
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn deletion_and_restoration_are_reported() {
        let p = temp_file("a");
        let mut m = monitor(&p);
        std::fs::remove_file(&p).unwrap();
        assert_eq!(m.check()[0].kind, FindingKind::Deleted);
        assert!(m.is_compromised());
        std::fs::write(&p, "a").unwrap();
        assert_eq!(m.check()[0].kind, FindingKind::Restored);
        assert!(!m.is_compromised());
        std::fs::remove_file(p).ok();
    }

    #[test]
    fn a_file_missing_at_start_is_listed_as_unprotected_not_alerted() {
        let p = std::env::temp_dir().join(format!("iam-integrity-missing-{}", Uuid::new_v4()));
        let mut m = monitor(&p);
        assert_eq!(m.unprotected(), vec!["config"]);
        assert!(m.check().is_empty());
        assert!(!m.is_compromised());
    }
}
