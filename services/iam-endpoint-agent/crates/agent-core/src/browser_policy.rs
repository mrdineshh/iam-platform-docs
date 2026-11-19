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
//! - Chrome and Edge `URLBlocklist`: the sign-in pages through which a PERSONAL Microsoft account (outlook.com, hotmail.com, live.com)
//!   authenticates are blocked, so such an account cannot be used on the web in these browsers. This is the spec's fallback for
//!   Microsoft ("otherwise apply documented browser/domain controls", Section 8.2): a lower-assurance domain control, NOT the
//!   Entra tenant control (which needs an Entra tenant). Work and school accounts sign in elsewhere and are not touched.
//!   An administrator switches it on and off from the Admin Console (signed policy, see `sync.rs`); it is off by default.
//!
//! Firefox, Safari, Entra tenant restrictions and the other-provider adapters (P1-21/22/24/25) are not covered here.

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

    /// Makes sure the browser's URL block list holds `list.urls`, keeping everything else already on it (see
    /// [`merge_block_list`]). Unlike [`apply`](Self::apply) this has to READ the current list first.
    fn merge_url_blocklist(&self, list: &UrlBlockList) -> Result<(), BrowserPolicyError>;

    /// Takes `list.urls` off the browser's URL block list again, keeping everything else (see [`remove_from_block_list`]).
    /// A browser that has no such list is already fine: that is success, not an error.
    fn remove_url_blocklist(&self, list: &UrlBlockList) -> Result<(), BrowserPolicyError>;
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

/// The hosts a personal Microsoft account (outlook.com, hotmail.com, live.com, msn.com) signs in through. Work and school
/// accounts use login.microsoftonline.com and are deliberately not listed.
pub const PERSONAL_MICROSOFT_HOSTS: [&str; 4] = ["login.live.com", "outlook.live.com", "account.live.com", "signup.live.com"];

/// One browser's URL block list: where it lives (a sub-key of its policy key, with numbered values "1", "2", ...) and the
/// URLs this agent wants on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UrlBlockList {
    pub browser: &'static str,
    /// The browser's policy key; the list itself is the `URLBlocklist` sub-key below it.
    pub key_path: &'static str,
    pub urls: Vec<String>,
}

/// The block list this agent maintains in each browser for personal Microsoft sign-in. Whether it is on the list is the
/// administrator's choice, made centrally and delivered in the signed policy.
pub fn personal_microsoft_lists() -> Vec<UrlBlockList> {
    let urls: Vec<String> = PERSONAL_MICROSOFT_HOSTS.iter().map(|h| h.to_string()).collect();
    vec![
        UrlBlockList { browser: "Chrome", key_path: r"SOFTWARE\Policies\Google\Chrome", urls: urls.clone() },
        UrlBlockList { browser: "Edge", key_path: r"SOFTWARE\Policies\Microsoft\Edge", urls },
    ]
}

/// What a browser's block list should hold after the agent has had its say: everything already on it that is not ours, in its
/// original order, then ours. Case-insensitive, no duplicates, and idempotent. Anything somebody else put on the list (a
/// company's own group policy, say) is kept; a browser reads such a list only up to its first gap, so the caller writes the
/// result back as consecutive entries "1".."N".
pub fn merge_block_list(existing: &[String], ours: &[String]) -> Vec<String> {
    let is_ours = |u: &str| ours.iter().any(|o| o.trim().eq_ignore_ascii_case(u.trim()));
    let mut merged: Vec<String> = Vec::new();
    for e in existing {
        let e = e.trim();
        if e.is_empty() || is_ours(e) || merged.iter().any(|m| m.eq_ignore_ascii_case(e)) {
            continue;
        }
        merged.push(e.to_string());
    }
    for o in ours {
        let o = o.trim();
        if !o.is_empty() && !merged.iter().any(|m| m.eq_ignore_ascii_case(o)) {
            merged.push(o.to_string());
        }
    }
    merged
}

/// The block list after taking ours off: everything that is not ours, in its original order. The mirror of [`merge_block_list`]
/// (case-insensitive, trimmed, no blanks or duplicates), so merging and then removing leaves a list exactly as it was apart from
/// tidying. Removing from a list without ours changes nothing.
pub fn remove_from_block_list(existing: &[String], ours: &[String]) -> Vec<String> {
    let is_ours = |u: &str| ours.iter().any(|o| o.trim().eq_ignore_ascii_case(u.trim()));
    let mut kept: Vec<String> = Vec::new();
    for e in existing {
        let e = e.trim();
        if e.is_empty() || is_ours(e) || kept.iter().any(|k| k.eq_ignore_ascii_case(e)) {
            continue;
        }
        kept.push(e.to_string());
    }
    kept
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

    // ---- personal Microsoft sign-in block ----

    #[test]
    fn the_personal_microsoft_lists_cover_chrome_and_edge() {
        let lists = personal_microsoft_lists();
        assert_eq!(lists.len(), 2);
        for list in &lists {
            assert!(list.urls.contains(&"login.live.com".to_string()), "{}", list.browser);
            assert!(list.urls.contains(&"outlook.live.com".to_string()), "{}", list.browser);
        }
        assert!(lists.iter().any(|l| l.browser == "Chrome" && l.key_path == r"SOFTWARE\Policies\Google\Chrome"));
        assert!(lists.iter().any(|l| l.browser == "Edge" && l.key_path == r"SOFTWARE\Policies\Microsoft\Edge"));
    }

    #[test]
    fn never_blocks_the_work_and_school_sign_in() {
        // Work and school accounts sign in at login.microsoftonline.com and use office.com / microsoft.com.
        for host in PERSONAL_MICROSOFT_HOSTS {
            assert!(host.ends_with(".live.com"), "{host}");
            for work in ["microsoftonline", "office.com", "microsoft.com", "office365", "sharepoint"] {
                assert!(!host.contains(work), "{host} must not touch {work}");
            }
        }
    }

    // ---- merging into an existing block list ----

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn keeps_what_somebody_else_put_on_the_list_and_adds_ours_after_it() {
        let merged = merge_block_list(&strings(&["facebook.com", "example.org"]), &strings(&["login.live.com", "outlook.live.com"]));
        assert_eq!(merged, strings(&["facebook.com", "example.org", "login.live.com", "outlook.live.com"]));
    }

    #[test]
    fn an_empty_list_just_gets_ours() {
        assert_eq!(merge_block_list(&[], &strings(&["login.live.com"])), strings(&["login.live.com"]));
    }

    #[test]
    fn running_it_again_changes_nothing() {
        let ours = strings(&["login.live.com", "outlook.live.com"]);
        let once = merge_block_list(&strings(&["facebook.com"]), &ours);
        assert_eq!(merge_block_list(&once, &ours), once);
    }

    #[test]
    fn our_entries_already_present_in_any_case_are_not_doubled() {
        let merged = merge_block_list(&strings(&["LOGIN.live.com", "facebook.com", "  outlook.live.com "]), &strings(&["login.live.com", "outlook.live.com"]));
        assert_eq!(merged, strings(&["facebook.com", "login.live.com", "outlook.live.com"]));
    }

    #[test]
    fn blank_and_duplicate_foreign_entries_are_dropped() {
        let merged = merge_block_list(&strings(&["a.com", "", "  ", "A.com", "b.com"]), &strings(&["login.live.com"]));
        assert_eq!(merged, strings(&["a.com", "b.com", "login.live.com"]));
    }

    // ---- taking ours off again ----

    #[test]
    fn removing_keeps_what_somebody_else_put_on_the_list() {
        let ours = strings(&["login.live.com", "outlook.live.com"]);
        let removed = remove_from_block_list(&strings(&["facebook.com", "login.live.com", "example.org", "outlook.live.com"]), &ours);
        assert_eq!(removed, strings(&["facebook.com", "example.org"]));
    }

    #[test]
    fn removing_from_a_list_without_ours_changes_nothing() {
        let ours = strings(&["login.live.com"]);
        assert_eq!(remove_from_block_list(&strings(&["a.com", "b.com"]), &ours), strings(&["a.com", "b.com"]));
        assert!(remove_from_block_list(&[], &ours).is_empty());
    }

    #[test]
    fn removal_matches_in_any_case_and_ignores_padding() {
        let removed = remove_from_block_list(&strings(&["LOGIN.live.com", " Outlook.Live.com ", "a.com"]), &strings(&["login.live.com", "outlook.live.com"]));
        assert_eq!(removed, strings(&["a.com"]));
    }

    #[test]
    fn adding_then_removing_leaves_the_list_as_it_was() {
        let ours = strings(&["login.live.com", "outlook.live.com"]);
        let before = strings(&["facebook.com", "example.org"]);
        let after_add = merge_block_list(&before, &ours);
        assert_eq!(remove_from_block_list(&after_add, &ours), before);
    }

    #[test]
    fn removing_all_of_ours_from_a_list_that_only_held_ours_leaves_it_empty() {
        let ours = strings(&["login.live.com"]);
        assert!(remove_from_block_list(&merge_block_list(&[], &ours), &ours).is_empty());
    }
}
