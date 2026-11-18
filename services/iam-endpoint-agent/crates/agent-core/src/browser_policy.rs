//! Browser identity restriction (spec P1-19 / P1-20 / P1-23): stop a managed browser from signing in to a
//! personal account, using the browsers' own enterprise policy and NOT a TLS-inspecting proxy (AP-7).
//!
//! This module is pure: it turns a list of allowed email domains into the exact policy values to write. Writing
//! them (the Windows registry) is the platform adapter's job, behind [`BrowserPolicyApplier`], so everything
//! here is unit-tested on any OS.
//!
//! Policies written (HKLM, so a standard user cannot change them):
//! - Chrome and Edge `RestrictSigninToPattern`: only accounts whose email matches the regex may sign in to the browser.
//! - Chrome `AllowedDomainsForApps`: Google sign-in is only accepted for the listed Workspace domains (blocks a
//!   personal Gmail account on Google services).
//!
//! Firefox, Safari and the other-provider adapters (P1-21/22/24/25) are not covered here.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyValue {
    String(String),
}

/// One registry value under `HKEY_LOCAL_MACHINE`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEntry {
    pub browser: &'static str,
    pub key_path: &'static str,
    pub name: &'static str,
    pub value: PolicyValue,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BrowserPolicyError {
    #[error("{0:?} is not a valid email domain (use names like example.com)")]
    InvalidDomain(String),
    #[error("could not apply browser policy: {0}")]
    Apply(String),
}

pub trait BrowserPolicyApplier {
    fn apply(&self, entries: &[PolicyEntry]) -> Result<(), BrowserPolicyError>;
}

/// Lower-cases and validates a domain. Deliberately strict: the value ends up inside a regular expression
/// and a comma-separated list, so anything beyond letters, digits, hyphens and dots is rejected outright
/// rather than escaped.
pub fn normalize_domain(raw: &str) -> Result<String, BrowserPolicyError> {
    let d = raw.trim().to_ascii_lowercase();
    let valid = d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|label| {
            !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-') && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    if valid {
        Ok(d)
    } else {
        Err(BrowserPolicyError::InvalidDomain(raw.to_string()))
    }
}

/// The policy values for the given allowed domains. An empty list yields no entries: the feature is off and
/// the agent leaves browser policy alone.
pub fn chromium_entries(allowed_domains: &[String]) -> Result<Vec<PolicyEntry>, BrowserPolicyError> {
    if allowed_domains.is_empty() {
        return Ok(Vec::new());
    }
    let mut domains = allowed_domains.iter().map(|d| normalize_domain(d)).collect::<Result<Vec<_>, _>>()?;
    domains.sort();
    domains.dedup();

    let pattern = format!(".*@({})$", domains.iter().map(|d| d.replace('.', "\\.")).collect::<Vec<_>>().join("|"));
    Ok(vec![
        PolicyEntry { browser: "Chrome", key_path: r"SOFTWARE\Policies\Google\Chrome", name: "RestrictSigninToPattern", value: PolicyValue::String(pattern.clone()) },
        PolicyEntry { browser: "Chrome", key_path: r"SOFTWARE\Policies\Google\Chrome", name: "AllowedDomainsForApps", value: PolicyValue::String(domains.join(",")) },
        PolicyEntry { browser: "Edge", key_path: r"SOFTWARE\Policies\Microsoft\Edge", name: "RestrictSigninToPattern", value: PolicyValue::String(pattern) },
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_list_changes_nothing() {
        assert!(chromium_entries(&[]).unwrap().is_empty());
    }

    #[test]
    fn builds_pattern_and_domain_list_for_chrome_and_edge() {
        let e = chromium_entries(&domains(&["Econz.net", "example.com"])).unwrap();
        assert_eq!(e.len(), 3);
        let pattern = r".*@(econz\.net|example\.com)$";
        assert!(e.iter().any(|x| x.browser == "Chrome" && x.name == "RestrictSigninToPattern" && x.value == PolicyValue::String(pattern.into())));
        assert!(e.iter().any(|x| x.browser == "Edge" && x.name == "RestrictSigninToPattern" && x.value == PolicyValue::String(pattern.into())));
        assert!(e.iter().any(|x| x.name == "AllowedDomainsForApps" && x.value == PolicyValue::String("econz.net,example.com".into())));
    }

    #[test]
    fn duplicates_collapse_and_order_is_stable() {
        let a = chromium_entries(&domains(&["b.com", "a.com", "A.com"])).unwrap();
        let b = chromium_entries(&domains(&["a.com", "b.com"])).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn rejects_values_that_could_break_the_regex_or_list() {
        for bad in ["", "localhost", "a.com|evil.com", "a.com,b.com", "*.com", "a b.com", "-a.com", "a..com", "a.com)(", "a.com\\"] {
            assert!(chromium_entries(&domains(&[bad])).is_err(), "{bad:?} should be rejected");
        }
    }

    #[test]
    fn one_bad_domain_rejects_the_whole_list() {
        assert!(chromium_entries(&domains(&["good.com", "bad domain"])).is_err());
    }
}
