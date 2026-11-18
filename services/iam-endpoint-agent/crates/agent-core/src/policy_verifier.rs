use crate::api_client::DevicePolicyResponse;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::DateTime;
use ed25519_dalek::{Signature, VerifyingKey};
use uuid::Uuid;

/// Must match `DevicePolicyCanonical.FORMAT` in iam-tenant-svc exactly.
pub const POLICY_FORMAT: &str = "iam-device-policy-v1";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyVerificationError {
    #[error("malformed configured transit public key: {0}")]
    MalformedPublicKey(String),
    #[error("malformed policy timestamp: {0}")]
    MalformedTimestamp(String),
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
    #[error("policy signature did not verify")]
    InvalidSignature,
    #[error("policy is validly signed but was issued for a different tenant")]
    WrongTenant,
    #[error("policy is validly signed but was issued for a different device (replay?)")]
    WrongDevice,
}

/// A device policy whose signature **and** tenant/device binding have been checked. The only way to
/// obtain one is [`verify_policy`]; everything downstream (the policy cache, local decisions) takes this
/// type, so "an unverified policy is never acted on" is enforced by the compiler, not by convention.
#[derive(Debug, Clone)]
pub struct VerifiedPolicy {
    policy: DevicePolicyResponse,
    issued_at: i64,
    expires_at: i64,
}

impl VerifiedPolicy {
    pub fn policy(&self) -> &DevicePolicyResponse {
        &self.policy
    }
    pub fn issued_at(&self) -> i64 {
        self.issued_at
    }
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }
    pub fn into_policy(self) -> DevicePolicyResponse {
        self.policy
    }
}

/// Checks a [`DevicePolicyResponse`] against the admin-configured OpenBao transit public key, and that it
/// was issued to *this* tenant and device (spec Section 15.3: "tenant/device bound"; Section 16: "signed,
/// versioned, expiry-bound and anti-rollback protected"). Expiry and rollback are time/state dependent and
/// are checked when the policy is *accepted* into the cache, see `policy_state::PolicyCache::accept`.
pub fn verify_policy(
    policy: DevicePolicyResponse,
    transit_public_key_base64: &str,
    expected_tenant: Uuid,
    expected_device: Uuid,
) -> Result<VerifiedPolicy, PolicyVerificationError> {
    // OpenBao/Vault transit Ed25519 public keys are raw 32-byte keys (not X.509 SPKI, unlike the device's
    // own key which this agent wraps for the backend's benefit -- see key_provider).
    let raw_key: [u8; 32] = STANDARD
        .decode(transit_public_key_base64)
        .map_err(|e| PolicyVerificationError::MalformedPublicKey(e.to_string()))?
        .try_into()
        .map_err(|_| PolicyVerificationError::MalformedPublicKey("expected a raw 32-byte Ed25519 key".into()))?;
    let verifying_key = VerifyingKey::from_bytes(&raw_key).map_err(|e| PolicyVerificationError::MalformedPublicKey(e.to_string()))?;

    let (canonical, issued_at, expires_at) = canonical_policy_encoding(&policy).map_err(PolicyVerificationError::MalformedTimestamp)?;

    // Vault/OpenBao prefix transit signatures with "vault:v<n>:" -- strip it before decoding.
    let raw_signature_b64 = policy.signature.rsplit(':').next().filter(|s| !s.is_empty()).ok_or_else(|| PolicyVerificationError::MalformedSignature("empty signature".into()))?;
    let signature_bytes: [u8; 64] = STANDARD
        .decode(raw_signature_b64)
        .map_err(|e| PolicyVerificationError::MalformedSignature(e.to_string()))?
        .try_into()
        .map_err(|_| PolicyVerificationError::MalformedSignature("expected a 64-byte Ed25519 signature".into()))?;

    verifying_key
        .verify_strict(canonical.as_bytes(), &Signature::from_bytes(&signature_bytes))
        .map_err(|_| PolicyVerificationError::InvalidSignature)?;

    // Only after the signature is good do the signed ids mean anything.
    if policy.tenant_id != expected_tenant {
        return Err(PolicyVerificationError::WrongTenant);
    }
    if policy.device_id != expected_device {
        return Err(PolicyVerificationError::WrongDevice);
    }

    Ok(VerifiedPolicy { policy, issued_at, expires_at })
}

/// Rebuilds the exact string iam-tenant-svc's `DevicePolicyCanonical.encode` signed. Applications are
/// encoded in the order received: the backend sorts them (as text) before both signing and returning.
fn canonical_policy_encoding(policy: &DevicePolicyResponse) -> Result<(String, i64, i64), String> {
    let issued_at = DateTime::parse_from_rfc3339(&policy.issued_at).map_err(|e| format!("issuedAt: {e}"))?.timestamp();
    let expires_at = DateTime::parse_from_rfc3339(&policy.expires_at).map_err(|e| format!("expiresAt: {e}"))?.timestamp();
    let apps = policy
        .applications
        .iter()
        .map(|a| format!("{}:{}:{}:{}:{}", a.application_id, a.pending_access, a.offline_access, a.offline_grace_seconds, a.failure_mode))
        .collect::<Vec<_>>()
        .join(";");
    let canonical = format!(
        "{POLICY_FORMAT}|{}|{}|{}|{}|{issued_at}|{expires_at}|{}|{}|{}|{}|{apps}",
        policy.tenant_id,
        policy.device_id,
        policy.policy_id,
        policy.policy_version,
        policy.device_status,
        policy.heartbeat_interval_seconds,
        policy.posture_interval_seconds,
        policy.agent_failure_mode,
    );
    Ok((canonical, issued_at, expires_at))
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::api_client::DeviceAppPolicy;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;

    pub const TENANT: &str = "11111111-1111-1111-1111-111111111111";
    pub const DEVICE: &str = "22222222-2222-2222-2222-222222222222";

    pub struct Fixture {
        pub signing_key: SigningKey,
        pub public_key_b64: String,
    }

    impl Fixture {
        pub fn new() -> Self {
            let signing_key = SigningKey::generate(&mut OsRng);
            let public_key_b64 = STANDARD.encode(signing_key.verifying_key().as_bytes());
            Self { signing_key, public_key_b64 }
        }

        /// A policy for TENANT/DEVICE, signed by this fixture's key.
        pub fn signed_policy(&self, version: i32, issued_at: i64, ttl: i64, status: &str, apps: Vec<DeviceAppPolicy>) -> DevicePolicyResponse {
            let mut p = unsigned_policy(version, issued_at, ttl, status, apps);
            self.sign(&mut p);
            p
        }

        pub fn sign(&self, p: &mut DevicePolicyResponse) {
            let (canonical, _, _) = canonical_policy_encoding(p).unwrap();
            p.signature = format!("vault:v1:{}", STANDARD.encode(self.signing_key.sign(canonical.as_bytes()).to_bytes()));
        }

        pub fn verified(&self, version: i32, issued_at: i64, ttl: i64, status: &str, apps: Vec<DeviceAppPolicy>) -> VerifiedPolicy {
            verify_policy(self.signed_policy(version, issued_at, ttl, status, apps), &self.public_key_b64, TENANT.parse().unwrap(), DEVICE.parse().unwrap()).unwrap()
        }
    }

    fn rfc3339(epoch: i64) -> String {
        DateTime::from_timestamp(epoch, 0).unwrap().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
    }

    pub fn unsigned_policy(version: i32, issued_at: i64, ttl: i64, status: &str, apps: Vec<DeviceAppPolicy>) -> DevicePolicyResponse {
        DevicePolicyResponse {
            tenant_id: TENANT.parse().unwrap(),
            device_id: DEVICE.parse().unwrap(),
            policy_id: "33333333-3333-3333-3333-333333333333".parse().unwrap(),
            policy_version: version,
            issued_at: rfc3339(issued_at),
            expires_at: rfc3339(issued_at + ttl),
            device_status: status.to_string(),
            heartbeat_interval_seconds: 300,
            posture_interval_seconds: 900,
            agent_failure_mode: "RISK_BASED".to_string(),
            applications: apps,
            signature: String::new(),
        }
    }

    pub fn app(id: &str, pending: bool, offline: bool, grace: i64, mode: &str) -> DeviceAppPolicy {
        DeviceAppPolicy { application_id: id.parse().unwrap(), pending_access: pending, offline_access: offline, offline_grace_seconds: grace, failure_mode: mode.to_string() }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    fn tenant() -> Uuid {
        TENANT.parse().unwrap()
    }
    fn device() -> Uuid {
        DEVICE.parse().unwrap()
    }

    /// The policy used by the golden vector (and by the OpenBao interop checks below).
    fn golden_policy() -> DevicePolicyResponse {
        let mut p = unsigned_policy(
            7,
            1_800_000_000,
            900,
            "APPROVED",
            vec![
                app("00000000-0000-0000-0000-000000000009", true, false, 0, "RISK_BASED"),
                app("44444444-4444-4444-4444-444444444444", false, true, 86400, "FAIL_CLOSED"),
                app("ffffffff-ffff-ffff-ffff-ffffffffffff", false, false, 0, "FAIL_OPEN"),
            ],
        );
        p.policy_id = "33333333-3333-3333-3333-333333333333".parse().unwrap();
        p
    }

    /// Byte-for-byte the same string as iam-tenant-svc's `DevicePolicyCanonicalTest.golden vector`.
    /// If the two ever disagree, one of the two tests fails -- instead of every device rejecting every policy.
    #[test]
    fn golden_vector_matches_the_backend() {
        let p = golden_policy();
        let (canonical, issued, expires) = canonical_policy_encoding(&p).unwrap();
        assert_eq!(
            canonical,
            "iam-device-policy-v1|11111111-1111-1111-1111-111111111111|22222222-2222-2222-2222-222222222222|\
             33333333-3333-3333-3333-333333333333|7|1800000000|1800000900|APPROVED|300|900|RISK_BASED|\
             00000000-0000-0000-0000-000000000009:true:false:0:RISK_BASED;\
             44444444-4444-4444-4444-444444444444:false:true:86400:FAIL_CLOSED;\
             ffffffff-ffff-ffff-ffff-ffffffffffff:false:false:0:FAIL_OPEN"
        );
        assert_eq!((issued, expires), (1_800_000_000, 1_800_000_900));
    }

    #[test]
    fn a_correctly_signed_policy_for_this_device_verifies() {
        let f = Fixture::new();
        let verified = verify_policy(f.signed_policy(3, 1_000, 900, "APPROVED", vec![]), &f.public_key_b64, tenant(), device()).unwrap();
        assert_eq!(verified.issued_at(), 1_000);
        assert_eq!(verified.expires_at(), 1_900);
    }

    #[test]
    fn a_tampered_status_fails() {
        let f = Fixture::new();
        let mut p = f.signed_policy(3, 1_000, 900, "SUSPENDED", vec![]);
        p.device_status = "APPROVED".into();
        assert_eq!(verify_policy(p, &f.public_key_b64, tenant(), device()).unwrap_err(), PolicyVerificationError::InvalidSignature);
    }

    #[test]
    fn fields_the_first_format_left_unsigned_are_now_covered() {
        // The first version of this format did not sign these three fields.
        let f = Fixture::new();
        for mutate in [
            (|p: &mut DevicePolicyResponse| p.heartbeat_interval_seconds = 3600) as fn(&mut DevicePolicyResponse),
            |p| p.posture_interval_seconds = 86_400,
            |p| p.agent_failure_mode = "FAIL_OPEN".into(),
        ] {
            let mut p = f.signed_policy(3, 1_000, 900, "APPROVED", vec![]);
            mutate(&mut p);
            assert_eq!(verify_policy(p, &f.public_key_b64, tenant(), device()).unwrap_err(), PolicyVerificationError::InvalidSignature);
        }
    }

    #[test]
    fn a_tampered_application_rule_fails() {
        let f = Fixture::new();
        let mut p = f.signed_policy(3, 1_000, 900, "APPROVED", vec![app("44444444-4444-4444-4444-444444444444", false, false, 0, "FAIL_CLOSED")]);
        p.applications[0].offline_grace_seconds = 999_999;
        assert_eq!(verify_policy(p, &f.public_key_b64, tenant(), device()).unwrap_err(), PolicyVerificationError::InvalidSignature);
    }

    #[test]
    fn a_signature_from_the_wrong_key_fails() {
        let f = Fixture::new();
        let other = Fixture::new();
        let p = f.signed_policy(3, 1_000, 900, "APPROVED", vec![]);
        assert_eq!(verify_policy(p, &other.public_key_b64, tenant(), device()).unwrap_err(), PolicyVerificationError::InvalidSignature);
    }

    #[test]
    fn a_validly_signed_policy_for_another_device_is_a_replay_and_is_rejected() {
        let f = Fixture::new();
        let mut p = unsigned_policy(3, 1_000, 900, "APPROVED", vec![]);
        p.device_id = "99999999-9999-9999-9999-999999999999".parse().unwrap(); // genuinely signed, but for someone else
        f.sign(&mut p);
        assert_eq!(verify_policy(p, &f.public_key_b64, tenant(), device()).unwrap_err(), PolicyVerificationError::WrongDevice);
    }

    #[test]
    fn a_validly_signed_policy_for_another_tenant_is_rejected() {
        let f = Fixture::new();
        let mut p = unsigned_policy(3, 1_000, 900, "APPROVED", vec![]);
        p.tenant_id = "99999999-9999-9999-9999-999999999999".parse().unwrap();
        f.sign(&mut p);
        assert_eq!(verify_policy(p, &f.public_key_b64, tenant(), device()).unwrap_err(), PolicyVerificationError::WrongTenant);
    }

    #[test]
    fn malformed_inputs_are_errors_not_panics() {
        let f = Fixture::new();
        let good = f.signed_policy(3, 1_000, 900, "APPROVED", vec![]);
        assert!(matches!(verify_policy(good.clone(), "not base64!!", tenant(), device()), Err(PolicyVerificationError::MalformedPublicKey(_))));
        assert!(matches!(verify_policy(good.clone(), "AAAA", tenant(), device()), Err(PolicyVerificationError::MalformedPublicKey(_))));
        let mut bad_time = good.clone();
        bad_time.issued_at = "yesterday".into();
        assert!(matches!(verify_policy(bad_time, &f.public_key_b64, tenant(), device()), Err(PolicyVerificationError::MalformedTimestamp(_))));
        let mut bad_sig = good;
        bad_sig.signature = "vault:v1:".into();
        assert!(matches!(verify_policy(bad_sig, &f.public_key_b64, tenant(), device()), Err(PolicyVerificationError::MalformedSignature(_))));
    }

    // ---- Interop with a REAL OpenBao transit key. Skipped in normal runs (`cargo test`); driven by the
    // verification script, which starts a throwaway OpenBao, runs infra/openbao/device-trust-setup.py against it,
    // signs the golden canonical string through the real transit API, and feeds the results back in here.
    // This is what proves the three independent pieces agree: Kotlin's signed text, OpenBao's signature format,
    // and this verifier.

    #[test]
    #[ignore = "driven by the OpenBao interop script"]
    fn interop_print_golden_canonical() {
        let (canonical, _, _) = canonical_policy_encoding(&golden_policy()).unwrap();
        println!("CANONICAL={canonical}");
    }

    #[test]
    #[ignore = "driven by the OpenBao interop script"]
    fn interop_a_real_openbao_signature_verifies_and_a_tampered_policy_does_not() {
        let public_key = std::env::var("INTEROP_PUBLIC_KEY").expect("INTEROP_PUBLIC_KEY");
        let signature = std::env::var("INTEROP_SIGNATURE").expect("INTEROP_SIGNATURE");

        let mut genuine = golden_policy();
        genuine.signature = signature.clone();
        verify_policy(genuine, &public_key, tenant(), device()).expect("a real OpenBao signature over the golden policy must verify");

        let mut tampered = golden_policy();
        tampered.signature = signature;
        tampered.device_status = "SUSPENDED".into();
        assert_eq!(verify_policy(tampered, &public_key, tenant(), device()).unwrap_err(), PolicyVerificationError::InvalidSignature);
    }
}
