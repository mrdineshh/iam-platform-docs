use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Hardware attributes collected for correlation/risk context only (spec
/// Section 5.1 table) -- never sufficient authentication on their own, and
/// never sent to the backend raw (Section 5.2: "do not use it as an
/// authentication credential"; the backend never sees raw serial/hardware
/// UUID either, see iam-tenant-svc's DeviceHardwareEntity comment). Each
/// field here is already whatever the platform layer could read -- this
/// module only hashes, it doesn't collect.
#[derive(Debug, Clone, Default)]
pub struct HardwareAttributes {
    pub manufacturer: Option<String>,
    pub model: Option<String>,
    pub os_version: Option<String>,
    pub hardware_uuid: Option<String>,
    pub serial_number: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceIdentity {
    /// Stable across re-enrolment attempts on the same install -- generated
    /// once and persisted (see secure_storage), never regenerated just
    /// because enrollment is retried (Section 5.1: "A locally generated
    /// UUID identifies the agent installation/enrolment instance").
    pub device_instance_id: Uuid,
}

impl DeviceIdentity {
    pub fn new() -> Self {
        Self { device_instance_id: Uuid::new_v4() }
    }
}

impl Default for DeviceIdentity {
    fn default() -> Self {
        Self::new()
    }
}

pub const FINGERPRINT_VERSION: i32 = 1;

/// Section 5.2's canonical_encode/SHA256 scheme, adapted: `tenant_scope` is
/// the configured tenant id (the agent doesn't know which *account's*
/// tenant it will end up bound to until enrollment completes, but it does
/// know which tenant it was configured for). Deterministic field order,
/// length-prefixed with a literal separator the way the spec warns
/// ambiguous concatenation must avoid -- values can't contain `|` in
/// practice (manufacturer/model strings), but each field is still wrapped
/// in its own hash-safe `len:value` segment to be certain.
pub fn fingerprint_hash(tenant_id: &str, platform: &str, hw: &HardwareAttributes) -> String {
    let mut canonical = String::new();
    for field in [
        Some(tenant_id),
        Some(platform),
        hw.manufacturer.as_deref(),
        hw.hardware_uuid.as_deref(),
        hw.model.as_deref(),
    ] {
        let value = field.unwrap_or("");
        canonical.push_str(&format!("{}:{}|", value.len(), value));
    }
    let digest = Sha256::digest(canonical.as_bytes());
    hex::encode(digest)
}

/// General-purpose SHA-256 hex hash for a single privacy-controlled raw
/// value (hardware UUID, serial number) before it's sent to the backend --
/// this service never sees the raw value (Section 5.2/11), only this.
/// Separate from [`fingerprint_hash`], which combines multiple fields with
/// its own canonical encoding; this is a plain single-value hash.
pub fn hash_value(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

// Minimal hex encode -- avoids pulling in the `hex` crate for one function;
// matches this codebase's existing "hand-rolled over an oversized dependency
// for something this small" precedent (see GoogleWorkspaceDirectoryClient's
// own flatJson comment on the Kotlin side).
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic_for_the_same_inputs() {
        let hw = HardwareAttributes { manufacturer: Some("Dell".into()), model: Some("Latitude".into()), ..Default::default() };
        let a = fingerprint_hash("tenant-1", "WINDOWS", &hw);
        let b = fingerprint_hash("tenant-1", "WINDOWS", &hw);
        assert_eq!(a, b);
        assert_eq!(a.len(), 64); // SHA-256 hex
    }

    #[test]
    fn fingerprint_differs_when_tenant_differs() {
        let hw = HardwareAttributes::default();
        let a = fingerprint_hash("tenant-1", "WINDOWS", &hw);
        let b = fingerprint_hash("tenant-2", "WINDOWS", &hw);
        assert_ne!(a, b);
    }
}
