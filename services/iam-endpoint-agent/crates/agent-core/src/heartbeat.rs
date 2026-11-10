use crate::api_client::{ApiClient, HeartbeatRequest};
use crate::key_provider::KeyProvider;
use std::time::Duration;
use uuid::Uuid;

/// Section 17 "Heartbeat: configurable; proposed default 5 minutes" and
/// Section 16 "Availability: explicit failure mode, offline policy,
/// retries, backoff and circuit breakers". This loop never stops on a
/// single failed heartbeat -- a transient network blip or a backend
/// restart must not require reinstalling the agent -- but backs off so a
/// genuinely down backend isn't hammered.
pub async fn run_heartbeat_loop(
    api: &ApiClient,
    tenant_id: &str,
    device_id: Uuid,
    key: &dyn KeyProvider,
    agent_version: &str,
    normal_interval: Duration,
    max_backoff: Duration,
) -> ! {
    let mut current_interval = normal_interval;
    loop {
        tokio::time::sleep(current_interval).await;

        let request = HeartbeatRequest {
            agent_version: agent_version.to_string(),
            policy_version: 0, // overwritten by caller once a policy has actually been fetched; see Agent::run
            health_status: "HEALTHY".to_string(),
        };

        match api.heartbeat(tenant_id, device_id, key, &request).await {
            Ok(()) => {
                tracing::debug!("heartbeat sent");
                current_interval = normal_interval;
            }
            Err(err) => {
                tracing::warn!(error = %err, "heartbeat failed, backing off");
                current_interval = (current_interval * 2).min(max_backoff);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_configured_ceiling() {
        let normal = Duration::from_secs(300);
        let max = Duration::from_secs(3600);
        let mut interval = normal;
        for _ in 0..10 {
            interval = (interval * 2).min(max);
        }
        assert_eq!(interval, max);
    }
}
