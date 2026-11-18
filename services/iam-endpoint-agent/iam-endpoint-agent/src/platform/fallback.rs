//! Non-Windows development fallback ONLY -- never shipped. Phase 1 targets
//! Windows exclusively (spec Section 2.1); this exists purely so
//! `agent_core`'s logic can be built, unit-tested, and manually smoke-run
//! on this repository's own Linux dev/CI environment, which has no Windows
//! host to build or test the real `windows.rs` path on. Collecting real
//! hardware attributes and opening a real browser both degrade to
//! best-effort stand-ins here.

use agent_core::device_identity::HardwareAttributes;
use agent_core::enrollment::BrowserLauncher;
use agent_core::posture::{PostureCollector, PostureError, PostureSignals};
use std::future::Future;

pub struct FallbackBrowserLauncher;

impl BrowserLauncher for FallbackBrowserLauncher {
    fn open(&self, url: &str) -> std::io::Result<()> {
        // Best-effort only: try xdg-open (Linux) then open (macOS); if neither exists, just log
        // the URL so a human can open it manually. The real Windows path (ShellExecuteW) is in
        // windows.rs and is what Phase 1 actually ships.
        for (cmd, args) in [("xdg-open", vec![url]), ("open", vec![url])] {
            if std::process::Command::new(cmd).args(&args).spawn().is_ok() {
                return Ok(());
            }
        }
        tracing::warn!(%url, "no browser launcher available on this platform; open this URL manually");
        Ok(())
    }
}

pub fn browser_launcher() -> Box<dyn BrowserLauncher> {
    Box::new(FallbackBrowserLauncher)
}

pub async fn collect_hardware_attributes() -> HardwareAttributes {
    HardwareAttributes {
        manufacturer: None,
        model: None,
        os_version: Some(std::env::consts::OS.to_string()),
        hardware_uuid: None,
        serial_number: None,
    }
}

/// Development stand-in: knows the OS name and nothing else, so every check reports UNKNOWN. It exists so the
/// agent's whole loop can run on a Linux or macOS developer machine; real posture is Windows-only (Phase 1).
pub struct FallbackPostureCollector;

impl PostureCollector for FallbackPostureCollector {
    fn collect(&self) -> impl Future<Output = Result<PostureSignals, PostureError>> + Send {
        async { Ok(PostureSignals { os_name: Some(std::env::consts::OS.to_string()), ..Default::default() }) }
    }
}

pub fn posture_collector() -> FallbackPostureCollector {
    FallbackPostureCollector
}

pub fn run_as_service<F>(run: F) -> anyhow::Result<()>
where
    F: FnOnce(tokio::sync::watch::Receiver<bool>) -> anyhow::Result<()>,
{
    tracing::info!("non-Windows fallback: running the agent loop directly in this process, not as an OS service");
    // Nothing ever signals shutdown here (Ctrl-C simply terminates the process), but the sender must
    // outlive `run`: the agent treats a dropped sender as "shut down now".
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    run(shutdown_rx)
}

/// No browser policy store off Windows: log what would be written so a development run shows the effect.
pub struct LoggingBrowserPolicy;

impl agent_core::browser_policy::BrowserPolicyApplier for LoggingBrowserPolicy {
    fn apply(&self, entries: &[agent_core::browser_policy::PolicyEntry]) -> Result<(), agent_core::browser_policy::BrowserPolicyError> {
        for e in entries {
            tracing::info!(browser = e.browser, key = e.key_path, name = e.name, "would set browser policy (not Windows)");
        }
        Ok(())
    }
}

pub fn browser_policy_applier() -> LoggingBrowserPolicy {
    LoggingBrowserPolicy
}

/// No OS event log off Windows: events go to the normal tracing output.
pub struct LoggingEventSink;

impl agent_core::local_log::LocalEventSink for LoggingEventSink {
    fn write(&self, severity: &str, event_type: &str, message: &str) {
        tracing::info!(severity, event_type, message, "agent event");
    }
}

pub fn local_event_log() -> LoggingEventSink {
    LoggingEventSink
}

/// No Windows service off Windows.
pub fn service_is_running() -> bool {
    false
}

/// No TPM key store off Windows: the agent always uses its software key.
pub fn hardware_key_store() -> Option<std::sync::Arc<dyn agent_core::key_provider::HardwareKeyStore>> {
    None
}

pub fn tpm_selftest(_user_scope: bool) -> anyhow::Result<()> {
    anyhow::bail!("TPM keys are only available on Windows")
}

/// No installer launcher off Windows: automatic updates are not available there.
pub fn update_installer() -> Option<std::sync::Arc<dyn agent_core::update::UpdateInstaller>> {
    None
}
