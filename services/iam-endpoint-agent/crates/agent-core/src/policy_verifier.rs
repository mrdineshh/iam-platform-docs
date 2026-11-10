use crate::api_client::DevicePolicyResponse;
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::DateTime;
use ed25519_dalek::{Signature, VerifyingKey};

#[derive(Debug, thiserror::Error)]
pub enum PolicyVerificationError {
    #[error("malformed configured transit public key: {0}")]
    MalformedPublicKey(String),
    #[error("malformed policy timestamp: {0}")]
    MalformedTimestamp(String),
    #[error("malformed signature: {0}")]
    MalformedSignature(String),
    #[error("policy signature did not verify -- rejecting (anti-tamper/anti-rollback, Section 16)")]
    InvalidSignature,
}

/// Verifies a [`DevicePolicyResponse`] against the admin-configured OpenBao
/// transit public key (Section 16: "Policy: signed, versioned, expiry-bound
/// and anti-rollback protected"). Must reproduce
/// DeviceTrustService.canonicalPolicyEncoding on the Kotlin side exactly,
/// field-for-field and separator-for-separator -- see that function's own
/// comment for why this is the single source of truth to keep in sync.
pub fn verify_policy(policy: &DevicePolicyResponse, transit_public_key_base64: &str) -> Result<(), PolicyVerificationError> {
    let public_key_der = STANDARD
        .decode(transit_public_key_base64)
        .map_err(|e| PolicyVerificationError::MalformedPublicKey(e.to_string()))?;
    // OpenBao/Vault transit Ed25519 public keys are returned as raw 32-byte
    // keys (not X.509 SPKI) -- unlike the device's own key, which this
    // agent wraps itself for the backend's benefit (see key_provider).
    let raw_key: [u8; 32] = public_key_der
        .try_into()
        .map_err(|_| PolicyVerificationError::MalformedPublicKey("expected a raw 32-byte Ed25519 key".into()))?;
    let verifying_key =
        VerifyingKey::from_bytes(&raw_key).map_err(|e| PolicyVerificationError::MalformedPublicKey(e.to_string()))?;

    let canonical = canonical_policy_encoding(policy).map_err(PolicyVerificationError::MalformedTimestamp)?;

    // OpenBao/Vault prefixes transit signatures with "vault:v<n>:" -- strip
    // that before decoding the raw Ed25519 signature bytes underneath.
    let raw_signature_b64 = policy
        .signature
        .rsplit(':')
        .next()
        .ok_or_else(|| PolicyVerificationError::MalformedSignature("empty signature".into()))?;
    let signature_bytes: [u8; 64] = STANDARD
        .decode(raw_signature_b64)
        .map_err(|e| PolicyVerificationError::MalformedSignature(e.to_string()))?
        .try_into()
        .map_err(|_| PolicyVerificationError::MalformedSignature("expected a 64-byte Ed25519 signature".into()))?;
    let signature = Signature::from_bytes(&signature_bytes);

    verifying_key
        .verify_strict(canonical.as_bytes(), &signature)
        .map_err(|_| PolicyVerificationError::InvalidSignature)
}

fn canonical_policy_encoding(policy: &DevicePolicyResponse) -> Result<String, String> {
    let issued_at = DateTime::parse_from_rfc3339(&policy.issued_at).map_err(|e| e.to_string())?.timestamp();
    let expires_at = DateTime::parse_from_rfc3339(&policy.expires_at).map_err(|e| e.to_string())?.timestamp();
    let apps_part = policy
        .applications
        .iter()
        .map(|a| format!("{}:{}:{}:{}:{}", a.application_id, a.pending_access, a.offline_access, a.offline_grace_seconds, a.failure_mode))
        .collect::<Vec<_>>()
        .join(";");
    Ok(format!("{}|{}|{}|{}|{}|{}", policy.policy_id, policy.policy_version, issued_at, expires_at, policy.device_status, apps_part))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rand::rngs::OsRng;
    use uuid::Uuid;

    fn sample_policy(signing_key: &SigningKey) -> DevicePolicyResponse {
        let mut policy = DevicePolicyResponse {
            policy_id: Uuid::new_v4(),
            policy_version: 3,
            issued_at: "2026-11-10T10:00:00Z".into(),
            expires_at: "2026-11-10T10:15:00Z".into(),
            device_status: "APPROVED".into(),
            heartbeat_interval_seconds: 300,
            posture_interval_seconds: 900,
            agent_failure_mode: "RISK_BASED".into(),
            applications: vec![],
            signature: String::new(),
        };
        let canonical = canonical_policy_encoding(&policy).unwrap();
        let signature = signing_key.sign(canonical.as_bytes());
        policy.signature = format!("vault:v1:{}", STANDARD.encode(signature.to_bytes()));
        policy
    }

    #[test]
    fn a_correctly_signed_policy_verifies() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key_b64 = STANDARD.encode(signing_key.verifying_key().as_bytes());
        let policy = sample_policy(&signing_key);

        assert!(verify_policy(&policy, &public_key_b64).is_ok());
    }

    #[test]
    fn a_tampered_field_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key_b64 = STANDARD.encode(signing_key.verifying_key().as_bytes());
        let mut policy = sample_policy(&signing_key);
        policy.device_status = "REVOKED".into(); // tampered after signing

        assert!(matches!(verify_policy(&policy, &public_key_b64), Err(PolicyVerificationError::InvalidSignature)));
    }

    #[test]
    fn a_signature_from_the_wrong_key_fails_verification() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let wrong_key = SigningKey::generate(&mut OsRng);
        let wrong_public_key_b64 = STANDARD.encode(wrong_key.verifying_key().as_bytes());
        let policy = sample_policy(&signing_key);

        assert!(matches!(verify_policy(&policy, &wrong_public_key_b64), Err(PolicyVerificationError::InvalidSignature)));
    }
}
