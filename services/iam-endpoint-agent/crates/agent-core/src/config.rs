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
}

fn default_heartbeat_interval() -> u64 {
    300
}
