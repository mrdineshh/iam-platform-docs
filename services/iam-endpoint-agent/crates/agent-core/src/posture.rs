//! Device posture: the facts the agent reports about the machine it runs on (BRD FR-5.4; PDF Sections 4.1, 13.3).
//!
//! The agent reports **facts only**. Whether they are acceptable is decided server-side
//! (`PostureEvaluator` in iam-tenant-svc), so a modified agent cannot simply claim to be compliant.
//!
//! Gathering is OS-specific and lives behind [`PostureCollector`] (the Windows one runs a fixed PowerShell
//! script, see `platform/windows.rs`). Everything here is OS-free so it is unit-tested on any machine.

use serde::{Deserialize, Serialize};
use std::future::Future;

/// A yes/no fact that may not be knowable. "Could not tell" is a distinct answer from "no": the server never
/// counts an unknown as a pass, but does not count it as a failure either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Tri {
    Enabled,
    Disabled,
    /// Also what any value this agent does not recognise becomes, instead of failing the whole report.
    #[default]
    #[serde(other)]
    Unknown,
}

/// Wire contract with iam-tenant-svc's Kotlin `PostureSignals` (same camelCase field names). Every field is
/// optional/defaulted: a probe that failed on this machine simply reports `UNKNOWN`/absent.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PostureSignals {
    pub os_name: Option<String>,
    pub os_version: Option<String>,
    pub os_build: Option<String>,
    /// BitLocker protection on the system drive.
    pub disk_encryption: Tri,
    /// Real-time antivirus protection (Windows Security Center, or Defender directly).
    pub antivirus: Tri,
    pub antivirus_product: Option<String>,
    /// All firewall profiles on.
    pub firewall: Tri,
    /// `Enabled` means a TPM is present.
    pub tpm_present: Tri,
    pub secure_boot: Tri,
    /// Date (`yyyy-MM-dd`) of the most recently installed update.
    pub last_hotfix_date: Option<String>,
    /// Epoch seconds, set by the agent when it sends the report.
    pub collected_at: Option<i64>,
}

#[derive(Debug, thiserror::Error)]
pub enum PostureError {
    #[error("posture collection failed: {0}")]
    Collect(String),
    #[error("collector produced no JSON object")]
    NoJson,
    #[error("collector output was not valid posture JSON: {0}")]
    Parse(#[from] serde_json::Error),
}

impl PostureSignals {
    /// Parses the collector's stdout. PowerShell can add stray lines around its output (progress, warnings,
    /// a UTF-8 byte-order mark), so the JSON object is cut out of the text rather than assuming the whole
    /// output is exactly one document.
    pub fn from_collector_output(output: &str) -> Result<Self, PostureError> {
        Ok(serde_json::from_str(json_object(output)?)?)
    }
}

/// The first `{` to the last `}` of `text`.
pub(crate) fn json_object(text: &str) -> Result<&str, PostureError> {
    match (text.find('{'), text.rfind('}')) {
        (Some(start), Some(end)) if start < end => Ok(&text[start..=end]),
        _ => Err(PostureError::NoJson),
    }
}

/// Gathers posture on this machine. May be slow (the Windows one shells out to PowerShell, several seconds),
/// so callers must not hold anything time-critical while awaiting it.
pub trait PostureCollector: Send + Sync {
    fn collect(&self) -> impl Future<Output = Result<PostureSignals, PostureError>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_full_report_parses() {
        let json = r#"{"osName":"Microsoft Windows 11 Pro","osVersion":"10.0.26100","osBuild":"26100",
            "diskEncryption":"ENABLED","antivirus":"ENABLED","antivirusProduct":"Windows Defender","firewall":"ENABLED",
            "tpmPresent":"ENABLED","secureBoot":"ENABLED","lastHotfixDate":"2026-10-14"}"#;
        let s = PostureSignals::from_collector_output(json).unwrap();
        assert_eq!(s.os_name.as_deref(), Some("Microsoft Windows 11 Pro"));
        assert_eq!((s.disk_encryption, s.antivirus, s.firewall, s.tpm_present, s.secure_boot), (Tri::Enabled, Tri::Enabled, Tri::Enabled, Tri::Enabled, Tri::Enabled));
        assert_eq!(s.antivirus_product.as_deref(), Some("Windows Defender"));
        assert_eq!(s.last_hotfix_date.as_deref(), Some("2026-10-14"));
    }

    #[test]
    fn missing_fields_and_unrecognised_values_become_unknown_instead_of_failing() {
        let s = PostureSignals::from_collector_output(r#"{"diskEncryption":"ENABLED","firewall":"MAYBE"}"#).unwrap();
        assert_eq!((s.disk_encryption, s.firewall, s.antivirus), (Tri::Enabled, Tri::Unknown, Tri::Unknown));
        assert_eq!(PostureSignals::from_collector_output("{}").unwrap(), PostureSignals::default());
    }

    #[test]
    fn null_values_from_a_failed_probe_are_accepted() {
        let s = PostureSignals::from_collector_output(r#"{"osName":null,"antivirusProduct":null,"lastHotfixDate":null,"diskEncryption":"DISABLED"}"#).unwrap();
        assert_eq!(s.disk_encryption, Tri::Disabled);
        assert!(s.os_name.is_none() && s.last_hotfix_date.is_none());
    }

    #[test]
    fn powershell_noise_around_the_json_is_tolerated() {
        let noisy = "\u{feff}WARNING: something harmless\r\n{\"firewall\":\"DISABLED\"}\r\nPS done\r\n";
        assert_eq!(PostureSignals::from_collector_output(noisy).unwrap().firewall, Tri::Disabled);
    }

    #[test]
    fn output_with_no_json_is_a_clear_error() {
        assert!(matches!(PostureSignals::from_collector_output("Access is denied"), Err(PostureError::NoJson)));
        assert!(matches!(PostureSignals::from_collector_output(""), Err(PostureError::NoJson)));
        assert!(matches!(PostureSignals::from_collector_output("{ not json }"), Err(PostureError::Parse(_))));
    }

    #[test]
    fn the_wire_format_matches_what_the_backend_expects() {
        // Exact key names and tri-state spellings iam-tenant-svc's Kotlin PostureSignals/PostureEvaluator read.
        let s = PostureSignals { disk_encryption: Tri::Disabled, antivirus: Tri::Enabled, collected_at: Some(1_800_000_000), ..Default::default() };
        let v: serde_json::Value = serde_json::to_value(&s).unwrap();
        assert_eq!(v["diskEncryption"], "DISABLED");
        assert_eq!(v["antivirus"], "ENABLED");
        assert_eq!(v["firewall"], "UNKNOWN");
        assert_eq!(v["collectedAt"], 1_800_000_000);
        assert!(v.get("disk_encryption").is_none(), "snake_case keys would be silently ignored by the backend");
    }
}
