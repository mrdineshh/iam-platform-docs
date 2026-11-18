use serde::{Deserialize, Serialize};

/// Static, per-install configuration -- not the signed device policy fetched
/// at runtime (that's [`crate::policy_client::DevicePolicy`]). An admin
/// bakes this into the installer per tenant (same "a human configures this
/// once, before the agent can do anything useful" pattern as every other
/// manual grant in this platform -- OpenBao mounts, Google domain-wide
/// delegation scopes, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Base URL of iam-tenant-svc's /api/v1/endpoint API (Section 10).
    pub backend_base_url: String,
    /// iam-login-portal's device-enrollment handoff route, e.g.
    /// `https://acme.platform.example.com/device-enroll` (Section 6.1 steps
    /// 3-4) -- see [`crate::enrollment`] for the loopback protocol.
    pub enrollment_login_url: String,
    pub tenant_id: String,
    /// Base64, X.509 SubjectPublicKeyInfo DER-encoded Ed25519 public key
    /// for OpenBao's "device-policy" transit signing key (see
    /// GoogleWorkspaceDirectoryClient-style reasoning: OpenBaoTransitClient
    /// on the backend signs with the matching private key, which never
    /// leaves OpenBao). An admin obtains this once via `vault read
    /// transit/keys/device-policy` and bakes it into this config -- see
    /// [`crate::policy_verifier`].
    pub device_policy_public_key_base64: String,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_seconds: u64,
    /// Email domains allowed to sign in to Chrome and Edge on this device (P1-19/20/23). Empty (the default)
    /// leaves browser policy untouched -- see [`crate::browser_policy`].
    #[serde(default)]
    pub allowed_identity_domains: Vec<String>,
    /// The loopback endpoint the company login page uses to prove a sign-in comes from this laptop
    /// ([`crate::local_api`]). On by default; set false to switch device-bound sign-in off on this machine.
    #[serde(default = "default_true")]
    pub local_api_enabled: bool,
    /// Use a TPM-backed device key when this machine has one (spec 5.3), falling back to a software key when it does
    /// not. Only affects NEW enrollments: an identity that already exists keeps the key it has. Set false to force
    /// software keys.
    #[serde(default = "default_true")]
    pub prefer_hardware_key: bool,
    /// Raw 32-byte Ed25519 PUBLIC key (base64) of the operator's `agent-release` signing key (docs/specs/agent-update-SPEC.md).
    /// Absent or empty = automatic updates are off. Only an administrator can set it (this file is administrators-only);
    /// nothing the platform sends can turn updates on.
    #[serde(default)]
    pub release_public_key_base64: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_heartbeat_interval() -> u64 {
    300
}

impl AgentConfig {
    /// Checked once, at start-up, for every mode -- so a mistake in the file fails immediately with a
    /// precise message rather than halfway through enrollment (or, worse, silently trusting nothing).
    pub fn validate(&self) -> Result<(), String> {
        if self.tenant_uuid()?.is_nil() {
            return Err("tenant_id is still the all-zero placeholder -- set it to your tenant's id".to_string());
        }
        require_secure_url("backend_base_url", &self.backend_base_url)?;
        require_secure_url("enrollment_login_url", &self.enrollment_login_url)?;
        use base64::{engine::general_purpose::STANDARD, Engine};
        let key = STANDARD
            .decode(self.device_policy_public_key_base64.trim())
            .map_err(|e| format!("device_policy_public_key_base64 is not valid base64: {e}"))?;
        if key.len() != 32 {
            return Err(format!("device_policy_public_key_base64 must be a raw 32-byte Ed25519 key, got {} bytes", key.len()));
        }
        crate::browser_policy::chromium_entries(&self.allowed_identity_domains).map_err(|e| format!("allowed_identity_domains: {e}"))?;
        if let Some(release_key) = self.release_public_key_base64.as_deref().map(str::trim).filter(|k| !k.is_empty()) {
            let raw = STANDARD.decode(release_key).map_err(|e| format!("release_public_key_base64 is not valid base64: {e}"))?;
            if raw.len() != 32 {
                return Err(format!("release_public_key_base64 must be a raw 32-byte Ed25519 key, got {} bytes", raw.len()));
            }
        }
        Ok(())
    }

    /// The tenant as a UUID -- policy verification binds a policy to this tenant, so a value that is not a
    /// valid UUID is a configuration error caught at start-up, not something to compare as free text.
    pub fn tenant_uuid(&self) -> Result<uuid::Uuid, String> {
        uuid::Uuid::parse_str(self.tenant_id.trim()).map_err(|e| format!("tenant_id {:?} is not a valid UUID: {e}", self.tenant_id))
    }
}

/// Everything this agent sends (device identity, signed requests) and opens (the sign-in page) must travel
/// over TLS (spec Section 16: "TLS 1.3; strict certificate validation"). Plain http is accepted only for a
/// loopback address, so local development works without weakening a real deployment.
fn require_secure_url(field: &str, value: &str) -> Result<(), String> {
    let url = reqwest::Url::parse(value).map_err(|e| format!("{field} is not a valid URL: {e}"))?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    match url.scheme() {
        "https" => Ok(()),
        "http" if loopback => Ok(()),
        "http" => Err(format!("{field} must use https (plain http is only allowed for localhost development)")),
        other => Err(format!("{field} must be an https URL, not {other}:")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(tenant_id: &str) -> AgentConfig {
        serde_json::from_value(serde_json::json!({
            "backend_base_url": "https://iam.example.com",
            "enrollment_login_url": "https://acme.example.com/device-enroll",
            "tenant_id": tenant_id,
            "device_policy_public_key_base64": "AAAA",
        }))
        .unwrap()
    }

    #[test]
    fn a_valid_tenant_uuid_parses_and_the_heartbeat_interval_defaults_to_300() {
        let c = config("11111111-1111-1111-1111-111111111111");
        assert_eq!(c.tenant_uuid().unwrap().to_string(), "11111111-1111-1111-1111-111111111111");
        assert_eq!(c.heartbeat_interval_seconds, 300);
    }

    #[test]
    fn an_invalid_tenant_id_is_a_clear_configuration_error() {
        assert!(config("acme").tenant_uuid().unwrap_err().contains("not a valid UUID"));
    }

    fn valid() -> serde_json::Value {
        serde_json::json!({
            "backend_base_url": "https://iam.example.com",
            "enrollment_login_url": "https://acme.example.com/device-enroll",
            "tenant_id": "11111111-1111-1111-1111-111111111111",
            // 32 zero bytes, base64
            "device_policy_public_key_base64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        })
    }

    fn check(patch: &[(&str, &str)]) -> Result<(), String> {
        let mut v = valid();
        for (k, val) in patch {
            v[*k] = serde_json::Value::String((*val).to_string());
        }
        serde_json::from_value::<AgentConfig>(v).unwrap().validate()
    }

    #[test]
    fn a_correct_config_validates() {
        assert_eq!(check(&[]), Ok(()));
    }

    #[test]
    fn the_shipped_sample_config_is_rejected_until_its_placeholders_are_replaced() {
        let sample: AgentConfig = serde_json::from_str(include_str!("../../../config.sample.json")).unwrap();
        assert!(sample.validate().unwrap_err().contains("placeholder"));
    }

    #[test]
    fn the_all_zero_placeholder_tenant_is_rejected_but_any_real_uuid_is_fine() {
        assert!(check(&[("tenant_id", "00000000-0000-0000-0000-000000000000")]).unwrap_err().contains("placeholder"));
        assert_eq!(check(&[("tenant_id", "7c9e6679-7425-40de-944b-e07fc1f90ae7")]), Ok(()));
    }

    #[test]
    fn urls_must_be_https_except_for_localhost_development() {
        assert!(check(&[("backend_base_url", "http://iam.example.com")]).unwrap_err().contains("must use https"));
        assert!(check(&[("enrollment_login_url", "ftp://iam.example.com/x")]).unwrap_err().contains("not ftp"));
        assert!(check(&[("backend_base_url", "not a url")]).unwrap_err().contains("not a valid URL"));
        assert_eq!(check(&[("backend_base_url", "http://127.0.0.1:8082")]), Ok(()));
        assert_eq!(check(&[("enrollment_login_url", "http://localhost:3001/device-enroll")]), Ok(()));
        // A look-alike host is not loopback.
        assert!(check(&[("backend_base_url", "http://127.0.0.1.evil.com")]).is_err());
    }

    #[test]
    fn the_transit_public_key_must_be_a_raw_32_byte_key() {
        assert!(check(&[("device_policy_public_key_base64", "%%%")]).unwrap_err().contains("not valid base64"));
        assert!(check(&[("device_policy_public_key_base64", "AAAA")]).unwrap_err().contains("32-byte"));
    }
}
